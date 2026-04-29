function Invoke-ListCippCveManagement {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Alert.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.tenantFilter
    $UseReportDB = $Request.Query.UseReportDB

    #$APIName      = $Request.Params.CIPPEndpoint

    try {
        $GraphRequest = Get-CIPPCVEReport -TenantFilter $TenantFilter -ErrorAction Stop
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        Write-Host "Error retrieving CVEs from report database: $($_.Exception.Message)"
        $StatusCode = [HttpStatusCode]::InternalServerError
        $GraphRequest = $_.Exception.Message
    }

    return ([HttpResponseContext]@{
                    StatusCode = $StatusCode
                    Body       = @($GraphRequest)
    })

    #    $CveCacheTable      = Get-CIPPTable -TableName 'CippReportingDB'
    #    $CveExceptionsTable = Get-CIPPTable -TableName 'CveExceptions'

    #    $Filter = if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
    #        "customerId eq '$TenantFilter'"
    #    } else {
    #        $null
    #    }

        #$CveEntries = if ($Filter) {
        #    Get-CIPPAzDataTableEntity @CveCacheTable -Filter $Filter
        #} else {
        #    Get-CIPPAzDataTableEntity @CveCacheTable
        #}

#        $AllExceptions   = Get-CIPPAzDataTableEntity @CveExceptionsTable
#        $ExceptionsByCve = @{}
#
#        foreach ($Ex in $AllExceptions) {
#            if (-not $ExceptionsByCve.ContainsKey($Ex.cveId)) {
#                $ExceptionsByCve[$Ex.cveId] = [System.Collections.Generic.List[object]]::new()
#            }
#            [void]$ExceptionsByCve[$Ex.cveId].Add([PSCustomObject]@{
#                customerId            = $Ex.customerId
#                exceptionType         = $Ex.exceptionType
#                exceptionComment      = $Ex.exceptionComment
#                exceptionCreatedBy    = $Ex.exceptionCreatedBy
#                exceptionReadableDate = $Ex.exceptionReadableDate
#                exceptionExpiry       = $Ex.exceptionExpiry
#            })
#        }

#        $SeverityOrder = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }

 #       $SortedCves = $GraphRequest | Group-Object -Property cveId | ForEach-Object {
  #          $CveGroup   = $_.Group
   #         $FirstEntry = $CveGroup[0]
#
 #           $DeviceCount = ($CveGroup | Select-Object -ExpandProperty deviceName -Unique).Count
  #          $TenantCount = ($CveGroup | Select-Object -ExpandProperty customerId -Unique).Count
#
 #           $HasException    = $CveGroup | Where-Object { $_.hasException -eq $true }
  #          $ExceptionStatus = if ($HasException) {
   #             $ExceptionSources = ($CveGroup | Where-Object { $_.hasException -eq $true } | Select-Object -ExpandProperty exceptionSource -Unique) -join ', '
    #            if ($HasException.Count -eq $CveGroup.Count) { "All ($ExceptionSources)" } else { "Partial ($ExceptionSources)" }
     #       } else { 'None' }
#
 #           $Exceptions = if ($ExceptionsByCve.ContainsKey($FirstEntry.cveId)) {
  #              @($ExceptionsByCve[$FirstEntry.cveId])
   #         } else {
    #            @()
     #       }
#
 #           $LatestException = if ($Exceptions.Count -gt 0) {
  #              $Exceptions | Sort-Object -Property exceptionReadableDate -Descending | Select-Object -First 1
   #         } else { $null }
#
 #           [PSCustomObject]@{
  #              cveId                      = $FirstEntry.cveId
   #             vulnerabilitySeverityLevel = $FirstEntry.vulnerabilitySeverityLevel
    #            exploitabilityLevel        = $FirstEntry.exploitabilityLevel
     #           softwareName               = $FirstEntry.softwareName
      #          softwareVendor             = $FirstEntry.softwareVendor
       #         softwareVersion            = $FirstEntry.softwareVersion
        #        deviceCount                = $DeviceCount
         #       tenantCount                = $TenantCount
          #      exceptionStatus            = $ExceptionStatus
           #     hasException               = [bool]$HasException
            #    affectedTenants            = ($CveGroup | Select-Object -ExpandProperty customerId -Unique) -join ', '
             #   affectedDevices            = ($CveGroup | Select-Object -ExpandProperty deviceName -Unique | Select-Object -First 10) -join ', '
              #  exceptions                 = $Exceptions
               # exceptionType              = $LatestException.exceptionType        ?? ''
                #exceptionComment           = $LatestException.exceptionComment      ?? ''
#                exceptionExpiry            = $LatestException.exceptionExpiry       ?? ''
 #           }
  #      } | Sort-Object -Property @{
  #          Expression = { $SeverityOrder[$_.vulnerabilitySeverityLevel] }
  #      }, @{
  #          Expression = { $_.deviceCount }
  #          Descending = $true
  #      }

#        return [HttpResponseContext]@{
#            StatusCode = [HttpStatusCode]::OK
#            Body       = @($SortedCves)
#        }

#    } catch {
#        $ErrorMessage = Get-CippException -Exception $_
#        Write-LogMessage -API $APIName -tenant $TenantFilter -message "Failed to retrieve CVE data: $($ErrorMessage.NormalizedError)" -sev 'Error' -LogData $ErrorMessage
#        return [HttpResponseContext]@{
#            StatusCode = [HttpStatusCode]::InternalServerError
#            Body       = @()
#        }
#    }
#}
