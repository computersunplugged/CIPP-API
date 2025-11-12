function Invoke-CIPPStandardNinjaCveSync {
    <#
    .SYNOPSIS
        Sync Microsoft Defender TVM vulnerabilities to NinjaOne (CSV upload to a scan group).
    .DESCRIPTION
        Headless Standard run. For the current $TenantFilter (MS Tenant ID):
          - Resolve Ninja Org ID from CippMapping (PartitionKey 'NinjaOneMapping', property 'IntegrationId')
          - Resolve Scan Group ID (Standard param > NinjaOneSettings)
          - Pull Defender TVM device<->CVE rows
          - Map to CSV using chosen device identifier ('hostname'|'ipAddress'|'macAddress')
          - Upload CSV to NinjaOne /v2/vulnerability/scan-groups/{id}/upload
    .PARAMETER Settings
    .PARAMETER Standard
        Expected optional parameters:
          - .Parameters.ScanGroupId
          - .Parameters.DeviceIdentifier   ('hostname'|'ipAddress'|'macAddress')  (defaults to 'hostname')
          - .Parameters.BaseUri            (defaults to https://api.ninjarmm.com)
    .PARAMETER TenantFilter
        Microsoft tenant ID currently being processed.
    .PARAMETER CustomerId
        CIPP internal customer reference (not required by this script).
    #>
    [CmdletBinding()]
    param(
        $Settings,
        $Standard,
        $TenantFilter,
        $CustomerId
    )

    Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'Ninja CVE Sync: start' -sev 'Info'

    try {
        # ------------------------------
        # 1) Resolve Ninja Org via CIPP mapping (Azure Table)
        # ------------------------------
        $mappingTable = Get-CIPPTable -TableName CippMapping

        # First try direct RowKey match; if not found, fetch the partition and match by a 'TenantId' property if present
        $mapEntity = $null
        try {
            $mapEntity = Get-AzDataTableEntity @mappingTable -PartitionKey 'NinjaOneMapping' -RowKey $TenantFilter -ErrorAction Stop
        } catch {
            # Fallback: pull all NinjaOneMapping rows and match where a TenantId property equals $TenantFilter
            $allNinjaRows = Get-AzDataTableEntity @mappingTable -Filter "PartitionKey eq 'NinjaOneMapping'"
            $mapEntity = $allNinjaRows |
                Where-Object {
                    $_.PSObject.Properties.Name -contains 'TenantId' -and $_.TenantId -eq $TenantFilter
                } |
                Select-Object -First 1
        }

        if (-not $mapEntity -or [string]::IsNullOrWhiteSpace($mapEntity.IntegrationId)) {
            throw "No Ninja mapping (IntegrationId) found in CippMapping for tenant $TenantFilter."
        }
        $ninjaOrgId = $mapEntity.IntegrationId

        # ------------------------------
        # 2) Resolve Scan Group ID
        # ------------------------------
        $scanGroupId = $null

        # 2a) Prefer Standard parameter (if you added a UI component)
        if ($Standard -and $Standard.Parameters -and $Standard.Parameters.ScanGroupId) {
            $scanGroupId = $Standard.Parameters.ScanGroupId
        }

        # 2b) Else read from NinjaOneSettings table keyed by org (PartitionKey 'NinjaConfig', RowKey = org id, property 'ScanGroupId')
        if (-not $scanGroupId) {
            $settingsTable = Get-CIPPTable -TableName NinjaOneSettings
            try {
                $row = Get-AzDataTableEntity @settingsTable -PartitionKey 'NinjaConfig' -RowKey $ninjaOrgId -ErrorAction Stop
                if ($row -and $row.ScanGroupId) { $scanGroupId = $row.ScanGroupId }
            } catch {
                # no row or different storage; fall through
            }
        }

        if (-not $scanGroupId) {
            throw "No Ninja Scan Group ID found. Provide via Standard parameter (ScanGroupId) or store in NinjaOneSettings (org $ninjaOrgId)."
        }

        # ------------------------------
        # 3) Get Ninja token (detect real signature; no hard assumptions)
        # ------------------------------
        $tokenCmd = Get-Command -Name Get-NinjaOneToken -ErrorAction SilentlyContinue
        if (-not $tokenCmd) { throw "Get-NinjaOneToken not found in the session." }

        $token = $null
        if ($tokenCmd.Parameters.ContainsKey('CustomerId')) {
            $token = Get-NinjaOneToken -CustomerId $CustomerId
        } elseif ($tokenCmd.Parameters.ContainsKey('TenantFilter')) {
            $token = Get-NinjaOneToken -TenantFilter $TenantFilter
        } else {
            $token = Get-NinjaOneToken
        }
        if (-not $token) { throw "Ninja token retrieval returned no result." }

        # ------------------------------
        # 4) HTTP target and headers
        # ------------------------------
        $baseUri = if ($Standard -and $Standard.Parameters -and $Standard.Parameters.BaseUri) {
            $Standard.Parameters.BaseUri
        } else {
            'https://api.ninjarmm.com' # default; override via parameter if your region differs
        }

        $headersHttp = @{
            'Authorization' = "Bearer $($token.access_token)"
            'Accept'        = 'application/json'
        }

        # ------------------------------
        # 5) Pull Defender TVM
        # ------------------------------
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

        # ------------------------------
        # 6) Map to CSV (hostname/ipAddress/macAddress). Default: hostname
        # ------------------------------
        $deviceIdentifier = 'hostname'
        if ($Standard -and $Standard.Parameters -and $Standard.Parameters.DeviceIdentifier) {
            $deviceIdentifier = $Standard.Parameters.DeviceIdentifier
        }

        $csvHeaders = @($deviceIdentifier, 'cveId')

        $mapped = foreach ($r in $rows) {
            $deviceVal = $null
            switch -Exact ($deviceIdentifier) {
                'hostname'   { $deviceVal = $r.deviceName }
                'ipAddress'  { $deviceVal = $r.ipAddress }     # include only if present in your TVM payload
                'macAddress' { $deviceVal = $r.macAddress }    # include only if present in your TVM payload
                default      { $deviceVal = $r.deviceName }
            }
            if ([string]::IsNullOrWhiteSpace($deviceVal)) { $deviceVal = $r.deviceName }

            if ($deviceVal -and $r.cveId) {
                [pscustomobject]@{
                    $deviceIdentifier = $deviceVal
                    cveId             = $r.cveId
                }
            }
        }

        # Filter out any nulls
        $mapped = $mapped | Where-Object { $_ }

        if (-not $mapped -or $mapped.Count -eq 0) {
            Write-LogMessage -API 'Standard' -tenant $TenantFilter -message 'No mappable rows after identifier filtering' -sev 'Warning'
            return [pscustomobject]@{
                TenantFilter = $TenantFilter
                StandardName = $Standard.DisplayName
                Result       = 'NoData'
                Count        = 0
                Message      = 'No rows had both device identifier and cveId'
                Timestamp    = (Get-Date)
            }
        }

        # ------------------------------
        # 7) Build CSV + upload
        # ------------------------------
        $csvBytes = New-VulnCsvBytes -Rows $mapped -Headers $csvHeaders
        $resp = Invoke-NinjaOneVulnCsvUpload -ScanGroupId $scanGroupId -CsvBytes $csvBytes -BaseUri $baseUri -Headers $headersHttp

        $processed = if ($resp -and $resp.PSObject.Properties.Name -contains 'recordsProcessed' -and $resp.recordsProcessed) {
            [int]$resp.recordsProcessed
        } else {
            $mapped.Count
        }

        Write-LogMessage -API 'Standard' -tenant $TenantFilter -message ("Ninja upload complete. RecordsProcessed: {0}" -f $processed) -sev 'Info'

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
