function Invoke-CIPPStandardNinjaCveSync {
    [CmdletBinding()]
    param(
        $Settings,
        $Standard,
        $TenantFilter,
        $CustomerId
    )

    Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'Ninja CVE Sync: start' -sev 'Info'

    try {
        # --- 1) Get Ninja auth context ---
        $token   = Get-NinjaOneToken -CustomerId $CustomerId
        $baseUri = 'https://api.ninjarmm.com'       # adjust if your environment uses region subdomain
        $headers = @{
            'Authorization' = "Bearer $($token.access_token)"
            'Accept'        = 'application/json'
        }

        # --- 2) Resolve Org & Scan Group ---
        $orgMap      = Get-NinjaOneOrgMapping -CustomerId $CustomerId
        $scanGroupId = $Standard.Parameters.ScanGroupId
        if (-not $scanGroupId -and $orgMap -and $orgMap.ScanGroupId) {
            $scanGroupId = $orgMap.ScanGroupId
        }
        if (-not $scanGroupId) {
            throw "No Scan Group ID found or defined for $($orgMap.NinjaOrgName)"
        }

        # --- 3) Fetch CVE data from Defender TVM ---
        $rows = Get-DefenderTvmRaw -TenantId $TenantFilter
        if (-not $rows -or $rows.Count -eq 0) {
            Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'No TVM rows found; skipping upload' -sev 'Info'
            return [pscustomobject]@{
                TenantFilter = $TenantFilter
                Result       = 'NoData'
                Count        = 0
                Message      = 'No vulnerabilities returned'
                Timestamp    = (Get-Date)
            }
        }

        # --- 4) Build CSV for Ninja ---
        $headersCsv = @('hostname','cveId')
        $mapped = foreach ($r in $rows) {
            [pscustomobject]@{
                hostname = $r.deviceName
                cveId    = $r.cveId
            }
        }
        $csvBytes = New-VulnCsvBytes -Rows $mapped -Headers $headersCsv

        # --- 5) Upload to Ninja ---
        $resp = Invoke-NinjaOneVulnCsvUpload -ScanGroupId $scanGroupId -CsvBytes $csvBytes -BaseUri $baseUri -Headers $headers
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