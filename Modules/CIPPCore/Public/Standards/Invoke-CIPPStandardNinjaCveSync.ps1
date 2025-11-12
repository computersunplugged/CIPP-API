function Invoke-CIPPStandardNinjaCveSync {
    [CmdletBinding()]
    param($Settings,$Standard,$TenantFilter,$CustomerId)

    Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'Ninja CVE Sync: start' -sev 'Info'

    try {
        # --- Resolve Ninja token (handle different function signatures) ---
        $tokenCmd = Get-Command -Name Get-NinjaOneToken -ErrorAction SilentlyContinue
        if (-not $tokenCmd) { throw "Get-NinjaOneToken not found" }

        if ($tokenCmd.Parameters.ContainsKey('CustomerId')) {
            $token = Get-NinjaOneToken -CustomerId $CustomerId
        } elseif ($tokenCmd.Parameters.ContainsKey('TenantFilter')) {
            $token = Get-NinjaOneToken -TenantFilter $TenantFilter
        } else {
            $token = Get-NinjaOneToken
        }
        if (-not $token) { throw "Ninja token retrieval returned nothing" }

        # --- Base URI (prefer a helper if you have one) ---
        $baseUri = 'https://api.ninjarmm.com'
        $headersHttp = @{
            'Authorization' = "Bearer $($token.access_token)"
            'Accept'        = 'application/json'
        }

        # --- Resolve Org mapping / Scan Group Id (flexible) ---
        $scanGroupId = $null

        $mapCmd = Get-Command -Name Get-NinjaOneOrgMapping -ErrorAction SilentlyContinue
        if ($mapCmd) {
            if ($mapCmd.Parameters.ContainsKey('CustomerId')) {
                $orgMap = Get-NinjaOneOrgMapping -CustomerId $CustomerId
            } elseif ($mapCmd.Parameters.ContainsKey('TenantFilter')) {
                $orgMap = Get-NinjaOneOrgMapping -TenantFilter $TenantFilter
            } else {
                $orgMap = Get-NinjaOneOrgMapping
            }

            # Try common property names used in mappings
            foreach ($prop in 'ScanGroupId','scanGroupId','VulnScanGroupId','VulnerabilityScanGroupId') {
                if ($orgMap -and ($orgMap | Get-Member -Name $prop -MemberType NoteProperty)) {
                    $scanGroupId = $orgMap.$prop; break
                }
            }
        }

        # Allow override from the Standard’s parameters (if UI components provided)
        # NOTE: Depending on your standards binding, these may be under $Standard.Parameters or
        # retrievable via a helper. Keep both checks for safety.
        $paramScan = $null
        if ($Standard -and $Standard.Parameters -and $Standard.Parameters.ScanGroupId) {
            $paramScan = $Standard.Parameters.ScanGroupId
        } elseif ($Settings) {
            try { $paramScan = Get-SettingsValue 'standards.NinjaCveSync.ScanGroupId' } catch {}
        }
        if ($paramScan) { $scanGroupId = $paramScan }

        if (-not $scanGroupId) {
            throw "No Ninja Scan Group ID resolved (mapping and parameters were empty)."
        }

        # --- Fetch Defender TVM rows (flat) ---
        $rows = Get-DefenderTvmRaw -TenantId $TenantFilter
        if (-not $rows -or $rows.Count -eq 0) {
            Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'No TVM rows found; skipping upload' -sev 'Info'
            return [pscustomobject]@{
                TenantFilter = $TenantFilter
                StandardName = $Standard.DisplayName
                Result       = 'NoData'
                Count        = 0
                Message      = 'No vulnerabilities returned'
                Timestamp    = (Get-Date)
            }
        }

        # --- Map to required CSV columns (adjust if your scan group uses ipAddress/macAddress) ---
        $csvHeaders = @('hostname','cveId')
        $mapped = foreach ($r in $rows) {
            [pscustomobject]@{
                hostname = $r.deviceName
                cveId    = $r.cveId
            }
        }

        $csvBytes = New-VulnCsvBytes -Rows $mapped -Headers $csvHeaders

        # --- Upload to Ninja ---
        $resp = Invoke-NinjaOneVulnCsvUpload -ScanGroupId $scanGroupId -CsvBytes $csvBytes -BaseUri $baseUri -Headers $headersHttp
        $processed = if ($resp.recordsProcessed) { [int]$resp.recordsProcessed } else { $mapped.Count }

        Write-LogMessage -API 'Standard' -tenant $TenantFilter -message ("Ninja upload complete. RecordsProcessed: {0}" -f $processed) -sev 'Info'
        return [pscustomobject]@{
            TenantFilter = $TenantFilter
            StandardName = $Standard.DisplayName
            Result       = 'OK'
            Count        = $processed
            Message      = "Uploaded to scan-group $scanGroupId"
            Timestamp    = (Get-Date)
        }
    }
    catch {
        $msg = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standard' -tenant $TenantFilter -message ("Ninja CVE Sync failed: {0}" -f $msg) -sev 'Error'
        return [pscustomobject]@{
            TenantFilter = $TenantFilter
            StandardName = $Standard.DisplayName
            Result       = 'Failed'
            Count        = 0
            Message      = $msg
            Timestamp    = (Get-Date)
        }
    }
}
