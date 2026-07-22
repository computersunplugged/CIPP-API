function Get-CIPPCVEReport {
    <#
    .SYNOPSIS
        Generates a CVE report from the CIPP Reporting database

    .DESCRIPTION
        Retrieves Defender CVE data for a tenant from the reporting database
        Optimized for high-performance cross-referencing and memory efficiency.

    .PARAMETER TenantFilter
        The tenant to generate the report for, or 'AllTenants'
    .PARAMETER UseReportDb
        Use cached results, True or False
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$UseReportDB
    )

    try {
        # Retrieve Exceptions from Exception database
        $CveExceptionsTable = Get-CIPPTable -TableName 'CveExceptions'
        $AllExceptions      = Get-CIPPAzDataTableEntity @CveExceptionsTable
        $ExceptionsByCve    = @{}
        $CveMasterTable     = @{}

        # Retrieve CVEs from database
        if ($UseReportDB -eq 'true'){
            $RawCveData    = Get-CIPPDbItem -TenantFilter 'allTenants' -Type 'DefenderCVEs' | Where-Object { $_.RowKey -ne 'DefenderCVEs-Count' }
            $AllCachedCves = $RawCveData.Data | ConvertFrom-Json
        } else {
            $AllCachedCves = get-DefenderCVEs -TenantFilter $TenantFilter
        }

        # Filter results by tenant
        if ($TenantFilter -eq 'AllTenants') {
            # Validate against active tenants to ensure we don't return orphaned data
            $TenantList = Get-Tenants -IncludeErrors
        } else {
            $TenantList = Get-Tenants | Where-Object defaultDomainName -eq $TenantFilter
        }

        # Filter CVEs by tenant and build CVE items
        foreach ($Item in $AllCachedCves) {
            if ($TenantList.defaultDomainName -contains $Item.customerId) {

                $CveId = $Item.PartitionKey

                if (-not $CveMasterTable.ContainsKey($CveId)) {
                    $CveMasterTable[$CveId] = @{
                        cveId                      = $CveId
                        vulnerabilitySeverityLevel = $Item.vulnerabilitySeverityLevel
                        exploitabilityLevel        = $Item.exploitabilityLevel
                        softwareName               = $Item.softwareName
                        softwareVendor             = $Item.softwareVendor
                        softwareVersion            = $Item.softwareVersion
                        lastUpdated                = $Item.lastUpdated
                        TotalDeviceCount           = 0
                        AffectedTenantsList        = [System.Collections.Generic.List[object]]::new()
                        AffectedDevicesList        = [System.Collections.Generic.List[object]]::new()
                        DiskPathList               = [System.Collections.Generic.List[object]]::new()
                        RegistryPathList           = [System.Collections.Generic.List[object]]::new()
                        ExceptionMatchCount        = 0
                        TotalTenantGroupCount      = 0
                    }
                }

                $CveGroup = $CveMasterTable[$CveId]
                $CveGroup.TotalTenantGroupCount++

                [void]$CveGroup.AffectedTenantsList.Add(@{ customerId = $Item.customerId })

                # Unpack the device JSON details from the row
                if ($Item.deviceDetailsJson) {
                    $Devices = ConvertFrom-Json $Item.deviceDetailsJson | Sort-Object -Property deviceName -Unique
                    foreach ($Dev in $Devices) {
                            [void]$CveGroup.AffectedDevicesList.Add(@{ deviceName    = $Dev.deviceName })
                            if($Dev.registryPaths){[void]$CveGroup.RegistryPathList.Add(@{ deviceName = $Dev.deviceName
                                                                                        registryPaths = $Dev.registryPaths })}
                            if($Dev.diskPaths){[void]$CveGroup.DiskPathList.Add(@{ deviceName = $Dev.deviceName
                                                                                diskPaths = $Dev.diskPaths })}
                            $CveGroup.TotalDeviceCount ++
                    }
                }
            }
        }

        # Filter exceptions by tenant and build exception items

        foreach ($Ex in $AllExceptions){

                if ($TenantList.defaultDomainName -contains $Ex.customerId -or $Ex.customerId -eq 'ALL'){
                    $CveId = $Ex.cveId

                    if (-not $ExceptionsByCve.ContainsKey($CveId)) {
                        $ExceptionsByCve[$CveId] = @{
                            cveId              = $Ex.cveId
                            customerId         = $Ex.customerId
                            exceptionSource    = $Ex.exceptionSource
                            exceptionType      = [System.Collections.Generic.List[object]]::new()
                            exceptionComment   = [System.Collections.Generic.List[object]]::new()
                            exceptionCreatedBy = [System.Collections.Generic.List[object]]::new()
                            exceptionDate      = [System.Collections.Generic.List[object]]::new()
                            exceptionExpiry    = [System.Collections.Generic.List[object]]::new()
                        }
                        [void]$ExceptionsByCve[$CveId].exceptionType.Add(@{ customerId = $Ex.customerId
                                                                    exceptionType = $Ex.exceptionType })
                        [void]$ExceptionsByCve[$CveId].exceptionComment.Add(@{ customerId = $Ex.customerId
                                                                    exceptionComment = $Ex.exceptionComment })
                        [void]$ExceptionsByCve[$CveId].exceptionCreatedBy.Add(@{ customerId = $Ex.customerId
                                                                    exceptionCreatedBy = $Ex.exceptionCreatedBy })
                        [void]$ExceptionsByCve[$CveId].exceptionDate.Add(@{ customerId = $Ex.customerId
                                                                    exceptionDate = $Ex.exceptionReadableDate })
                        [void]$ExceptionsByCve[$CveId].exceptionExpiry.Add(@{ customerId = $Ex.customerId
                                                                    exceptionExpiry = $Ex.exceptionExpiry })
                    } else {
                        # Handle duplicate exceptions
                        $ExceptionsByCve[$CveId].customerId         = $ExceptionsByCve[$CveId].customerId,$Ex.customerId
                        $ExceptionsByCve[$CveId].exceptionSource    = $ExceptionsByCve[$CveId].exceptionSource,$Ex.exceptionSource
                        [void]$ExceptionsByCve[$CveId].exceptionType.Add(@{ customerId = $Ex.customerId
                                                                    exceptionType = $Ex.exceptionType })
                        [void]$ExceptionsByCve[$CveId].exceptionComment.Add(@{ customerId = $Ex.customerId
                                                                    exceptionComment = $Ex.exceptionComment })
                        [void]$ExceptionsByCve[$CveId].exceptionCreatedBy.Add(@{ customerId = $Ex.customerId
                                                                    exceptionCreatedBy = $Ex.exceptionCreatedBy })
                        [void]$ExceptionsByCve[$CveId].exceptionDate.Add(@{ customerId = $Ex.customerId
                                                                    exceptionDate = $Ex.exceptionReadableDate })
                        [void]$ExceptionsByCve[$CveId].exceptionExpiry.Add(@{ customerId = $Ex.customerId
                                                                    exceptionExpiry = $Ex.exceptionExpiry })
                }
            }
            }

        # Combine filtered results
        $SortedCves = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($CveKey in $CveMasterTable.Keys) {
            $Target          = $CveMasterTable[$CveKey]
            $Exceptions      = $ExceptionsByCve[$CveKey]
            $ExceptionStatus = 'None'
            $HasException    = $false

            if ($Exceptions){
                $HasException       = $true
                $ExceptionStatus    = if ($Exceptions.customerId -contains "ALL") { "All" } else { "Partial" }
            }

            [void]$SortedCves.Add([PSCustomObject]@{
                cveId                      = $Target.cveId
                vulnerabilitySeverityLevel = $Target.vulnerabilitySeverityLevel
                exploitabilityLevel        = $Target.exploitabilityLevel
                softwareName               = $Target.softwareName
                softwareVendor             = $Target.softwareVendor
                softwareVersion            = $Target.softwareVersion
                deviceCount                = $Target.TotalDeviceCount
                tenantCount                = $Target.TotalTenantGroupCount
                registryPaths              = $Target.RegistryPathList
                diskPaths                  = $Target.DiskPathList
                exceptionStatus            = $ExceptionStatus
                hasException               = $HasException
                affectedTenants            = $Target.AffectedTenantsList
                affectedDevices            = $Target.AffectedDevicesList
                exceptionType              = $Exceptions.exceptionType ?? ''
                exceptionComment           = $Exceptions.exceptionComment ?? ''
                exceptionCreatedBy         = $Exceptions.exceptionCreatedBy ?? ''
                exceptionDate              = $Exceptions.exceptionDate ?? ''
                exceptionExpiry            = $Exceptions.exceptionExpiry ?? ''
                cacheTimeStamp             = $Target.lastUpdated
            })
        }

        return  $SortedCves | Sort-Object -Property cveId

    } catch {
        Write-LogMessage -API 'CVEReport' -tenant $TenantFilter -message "Failed to generate CVE report: $($_.Exception.Message)" -sev Error
        throw
    }
}
