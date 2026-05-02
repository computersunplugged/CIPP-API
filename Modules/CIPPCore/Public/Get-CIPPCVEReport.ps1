function Get-CIPPCVEReport {
    <#
    .SYNOPSIS
        Generates a CVE report from the CIPP Reporting database

    .DESCRIPTION
        Retrieves Defender CVE data for a tenant from the reporting database

    .PARAMETER TenantFilter
        The tenant to generate the report for

    .EXAMPLE
        Get-CIPPCVEReport -TenantFilter 'contoso.onmicrosoft.com'
        Gets all Cve data for the tenant from the report database
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    try {
        # Handle AllTenants
        if ($TenantFilter -eq 'AllTenants') {
            # Get all tenants that have CVE data
            $AllCVEItems = Get-CIPPDbItem -TenantFilter 'allTenants' -Type 'DefenderCVEs'
            $Tenants = @($AllCVEItems | Where-Object { $_.RowKey -ne 'DefenderCVEs-Count' } | Select-Object -ExpandProperty PartitionKey -Unique)

            $TenantList = Get-Tenants -IncludeErrors
            $Tenants = $Tenants | Where-Object { $TenantList.defaultDomainName -contains $_ }

            $AllResults = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($Tenant in $Tenants) {
                try {
                    $TenantResults = Get-CIPPCVEReport -TenantFilter $Tenant
                    foreach ($Result in $TenantResults) {
                        # Add Tenant property to each result
                        $Result | Add-Member -NotePropertyName 'Tenant' -NotePropertyValue $Tenant -Force
                        $AllResults.Add($Result)
                    }
                } catch {
                    Write-LogMessage -API 'CVEReport' -tenant $Tenant -message "Failed to get report for tenant: $($_.Exception.Message)" -sev Warning
                }
            }
            return $AllResults

            # Get CVEs from reporting DB
            $CVEItems = Get-CIPPDbItem -TenantFilter $TenantFilter -Type 'DefenderCVEs' | Where-Object { $_.RowKey -ne 'DefenderCVEs-Count' }

            if (-not $CVEItems) {
                throw 'No CVE data found in reporting database. Sync the report data first.'
            }

            # Get the most recent cache timestamp
            $CacheTimestamp = ($CVEItems | Where-Object { $_.Timestamp } | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp

            # Parse CVE data
            $AllCVEs = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($Item in $CVEItems | Where-Object { $_.RowKey -ne 'DefenderCVEs-Count' }) {

                # Special handling for deviceName - create array of objects

                $Property = $Item.Group | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | Sort-Object -Unique
                #if ($property -eq 'deviceName'){
                #$CVEData = @($Item.group.$property | ForEach-Object { @{ $property = $_ } })
                #} else {
                #$CVEData = $Item.Data | ConvertFrom-Json

                # Add cache timestamp
                $CVEData | Add-Member -NotePropertyName 'CacheTimestamp' -NotePropertyValue $CacheTimestamp -Force

                $AllCVEs.Add($CVEData)
                }
            }

            Write-LogMessage -API 'CVEReport' -tenant $TenantFilter -message "$Property"
            return $AllCVEs | Sort-Object -Property displayName
        }
    } catch {
        Write-LogMessage -API 'CVEReport' -tenant $TenantFilter -message "Failed to generate CVE report: $($_.Exception.Message)" -sev Error
        throw
    }
}
