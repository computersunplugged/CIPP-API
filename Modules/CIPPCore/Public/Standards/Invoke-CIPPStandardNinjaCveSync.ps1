function Invoke-CIPPStandardNinjaCveSync {
    <#
    .SYNOPSIS
        Sync Microsoft Defender TVM vulnerabilities to NinjaOne (CSV upload to a scan group).
    .DESCRIPTION
        Headless Standard run. For the current $TenantFilter (MS Tenant ID):
          - Resolve Ninja Org ID from CippMapping (PartitionKey 'NinjaOneMapping', RowKey = <TenantId>) → IntegrationId
          - Resolve Scan Group ID (prefer Standard parameter; else wire your own table lookup)
          - Pull Defender TVM device↔CVE rows
          - Map to CSV using chosen device identifier ('hostname'|'ipAddress'|'macAddress')
          - Upload CSV to NinjaOne /api/v2/vulnerability/scan-groups/{id}/upload
    .PARAMETER Settings
    .PARAMETER Standard
        Optional parameters:
          - .Parameters.ScanGroupId          (string)
          - .Parameters.DeviceIdentifier     (hostname|ipAddress|macAddress) default 'hostname'
    .PARAMETER TenantFilter
        Microsoft tenant ID currently being processed.
    .PARAMETER CustomerId
        CIPP internal customer reference (not required here).
    #>
    [CmdletBinding()]
    param(
        $Settings,
        $Standard,
        $TenantFilter,
        $CustomerId
    )

    Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'Ninja CVE Sync: start' -Sev 'Info'

    try {
        # 1) Configuration (CIPP default pattern)
        $cfgTable      = Get-CIPPTable -TableName Config
        $Configuration = ((Get-AzDataTableEntity @cfgTable).config | ConvertFrom-Json).NinjaOne
        if (-not $Configuration) { throw "NinjaOne configuration not found in Config table." }
        if (-not $Configuration.Instance) { throw "NinjaOne configuration missing 'Instance' host value." }

        # 2) Tenant → Ninja org mapping (strict RowKey match)
        $mapTable = Get-CIPPTable -TableName CippMapping
        $mapRow   = Get-AzDataTableEntity @mapTable -PartitionKey 'NinjaOneMapping' -RowKey $TenantFilter -ErrorAction Stop
        $ninjaOrgId = $mapRow.IntegrationId
        if (-not $ninjaOrgId) { throw "No IntegrationId for tenant $TenantFilter in NinjaOneMapping." }

        # 3) Scan Group Id (prefer Standard parameter; else wire your own lookup)
        $scanGroupId = $null
        if ($Standard -and $Standard.Parameters -and $Standard.Parameters.ScanGroupId) {
            $scanGroupId = $Standard.Parameters.ScanGroupId
        }
        if (-not $scanGroupId) {
            throw "No Ninja Scan Group ID provided. Set 'ScanGroupId' in the standard parameters or implement a table lookup."
        }

        # 4) Token (repo-accurate signature: -Configuration)
        $token = Get-NinjaOneToken -Configuration $Configuration
        if (-not $token -or -not $token.access_token) { throw "Failed to obtain NinjaOne token." }

        $headersHttp = @{
            'Authorization' = "Bearer $($token.access_token)"
            'Accept'        = 'application/json'
        }

        # 5) Pull Defender TVM rows
        $rows = Get-DefenderTvmRaw -TenantId $TenantFilter
        if (-not $rows -or $rows.Count -eq 0) {
            Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'No TVM rows found; skipping upload' -Sev 'Info'
            return [pscustomobject]@{
                TenantFilter = $TenantFilter
                StandardName = $Standard.DisplayName
                Result       = 'NoData'
                Count        = 0
                Message      = 'No vulnerabilities returned'
                Timestamp    = (Get-Date)
            }
        }

        # 6) Map to CSV
        $deviceIdentifier = 'hostname'
        if ($Standard -and $Standard.Parameters -and $Standard.Parameters.DeviceIdentifier) {
            $deviceIdentifier = $Standard.Parameters.DeviceIdentifier
        }
        if (@('hostname','ipAddress','macAddress') -notcontains $deviceIdentifier) {
            $deviceIdentifier = 'hostname'
        }

        $csvHeaders = @($deviceIdentifier, 'cveId')
        $mapped = foreach ($r in $rows) {
            # Prefer chosen identifier; fall back to deviceName if missing
            $deviceVal = $null
            switch -Exact ($deviceIdentifier) {
                'hostname'   { $deviceVal = $r.deviceName }
                'ipAddress'  { $deviceVal = $r.ipAddress }
                'macAddress' { $deviceVal = $r.macAddress }
                default      { $deviceVal = $r.deviceName }
            }
            if ([string]::IsNullOrWhiteSpace($deviceVal)) { $deviceVal = $r.deviceName }

            if ($deviceVal -and $r.cveId) {
                [pscustomobject]@{
                    $deviceIdentifier = $deviceVal
                    cveId             = $r.cveId
                }
            }
        } | Where-Object { $_ }

        if (-not $mapped -or $mapped.Count -eq 0) {
            Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'No mappable rows after identifier filtering' -Sev 'Warning'
            return [pscustomobject]@{
                TenantFilter = $TenantFilter
                StandardName = $Standard.DisplayName
                Result       = 'NoData'
                Count        = 0
                Message      = 'No rows had both device identifier and cveId'
                Timestamp    = (Get-Date)
            }
        }

        # 7) Build CSV + upload
        $csvBytes = New-VulnCsvBytes -Rows $mapped -Headers $csvHeaders
        $resp = Invoke-NinjaOneVulnCsvUpload -Instance $($Configuration.Instance) -ScanGroupId $scanGroupId -CsvBytes $csvBytes -Headers $headersHttp

        $processed = if ($resp -and $resp.PSObject.Properties.Name -contains 'recordsProcessed' -and $resp.recordsProcessed) {
            [int]$resp.recordsProcessed
        } else {
            $mapped.Count
        }

        Write-LogMessage -API 'Standard' -tenant $TenantFilter -message ("Ninja upload complete. RecordsProcessed: {0}" -f $processed) -Sev 'Info'

        return [pscustomobject]@{
            TenantFilter = $TenantFilter
            StandardName = $Standard.DisplayName
            Result       = 'OK'
            Count        = $processed
            Message      = "Uploaded to scan-group $scanGroupId (Org: $ninjaOrgId)"
            Timestamp    = (Get-Date)
        }
    }
    catch {
        $msg = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standard' -tenant $TenantFilter -message ("Ninja CVE Sync failed: {0}" -f $msg) -Sev 'Error'
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
