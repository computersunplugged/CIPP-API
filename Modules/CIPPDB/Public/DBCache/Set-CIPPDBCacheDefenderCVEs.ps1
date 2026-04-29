function Set-CIPPDBCacheDefenderCVEs {
    <#
    .SYNOPSIS
        Caches all vulnerabilities devices for a tenant

    .PARAMETER TenantFilter
        The tenant to cache vulnerabilities for

    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    try {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message 'Caching Defender CVEs' -sev Debug

        $Devices = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/devices?$top=999&$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,accountEnabled,approximateLastSignInDateTime' -tenantid $TenantFilter
        if (!$Devices) { $Devices = @() }
        Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'Devices' -Data @()
        Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'Devices' -Data @() -Count
        $Devices = $null

        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message 'Cached Azure AD devices successfully' -sev Debug

    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure AD devices: $($_.Exception.Message)" -sev Error
    }


    try {
        $AllVulns = Get-DefenderTvmRaw -TenantId $TenantFilter -MaxPages 0

        if (-not $AllVulns) {
            Write-LogMessage -API 'CveCacheRefresh' -tenant $TenantFilter -message "No vulnerability data returned from Defender TVM" -sev 'Warning'
            return
        }

        Write-LogMessage -API 'CveCacheRefresh' -tenant $TenantFilter -message "Retrieved $($AllVulns.Count) CVE records from Defender TVM" -sev 'Info'

        $Entities     = [System.Collections.Generic.List[object]]::new()
        $SkippedCount = 0

        foreach ($Vuln in $AllVulns) {

            [void]$Entities.Add(@{
                PartitionKey                 = $Vuln.cveId
                RowKey                       = "$TenantFilter`_$($Vuln.deviceName)"
                customerId                   = $TenantFilter
                id                           = $Vuln.id                           ?? ''
                deviceId                     = $Vuln.deviceId                     ?? ''
                deviceName                   = $Vuln.deviceName                   ?? ''
                osPlatform                   = $Vuln.osPlatform                   ?? ''
                osVersion                    = $Vuln.osVersion                    ?? ''
                osArchitecture               = $Vuln.osArchitecture               ?? ''
                softwareVendor               = $Vuln.softwareVendor               ?? ''
                softwareName                 = $Vuln.softwareName                 ?? ''
                softwareVersion              = $Vuln.softwareVersion              ?? ''
                cveId                        = $Vuln.cveId
                vulnerabilitySeverityLevel   = $Vuln.vulnerabilitySeverityLevel   ?? ''
                recommendedSecurityUpdate    = $Vuln.recommendedSecurityUpdate    ?? ''
                recommendedSecurityUpdateId  = $Vuln.recommendedSecurityUpdateId  ?? ''
                recommendedSecurityUpdateUrl = $Vuln.recommendedSecurityUpdateUrl ?? ''
                diskPaths                    = if ($Vuln.diskPaths)     { $Vuln.diskPaths -join ';' }     else { '' }
                registryPaths                = if ($Vuln.registryPaths) { $Vuln.registryPaths -join ';' } else { '' }
                lastSeenTimestamp            = $Vuln.lastSeenTimestamp            ?? ''
                firstSeenTimestamp           = $Vuln.firstSeenTimestamp           ?? ''
                exploitabilityLevel          = $Vuln.exploitabilityLevel          ?? ''
                recommendationReference      = $Vuln.recommendationReference      ?? ''
                rbacGroupName                = $Vuln.rbacGroupName                ?? ''
                lastUpdated                  = [string]$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z')
            })
        }

        if ($Entities.Count -eq 0) {
            Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "No valid CVE records to cache" -sev 'Warning'
            return
        }

        $SuccessCount = 0
        $FailCount    = 0
        $BatchSize    = 50
        $TotalBatches = [Math]::Ceiling($Entities.Count / $BatchSize)

        for ($i = 0; $i -lt $Entities.Count; $i += $BatchSize) {
            $BatchNumber = [Math]::Floor($i / $BatchSize) + 1
            $Batch       = $Entities[$i..[Math]::Min($i + $BatchSize - 1, $Entities.Count - 1)]

            try {
                Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'DefenderCVEs' -Data $Batch
                $SuccessCount += $Batch.Count
            } catch {
                $ErrorMessage  = Get-CippException -Exception $_
                $FailCount    += $Batch.Count
                Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Batch $BatchNumber/$TotalBatches failed: $($ErrorMessage.NormalizedError)" -sev 'Error' -LogData $ErrorMessage
            }
        }

        $UniqueCves    = ($Entities | Select-Object -ExpandProperty cveId -Unique).Count

        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "CVE Cache Refresh complete — $UniqueCves unique CVEs cached Written: $SuccessCount, Failed: $FailCount" -sev 'Info'

    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "CVE Cache Refresh failed: $($ErrorMessage.NormalizedError)" -sev 'Error' -LogData $ErrorMessage
        throw
    }
}
