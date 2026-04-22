function Invoke-ExecRemoveCippCveException {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Alert.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName      = $Request.Params.CIPPEndpoint
    $Headers      = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        $CveId       = $Request.Query.cveId
        $RemoveScope = $Request.Query.removeScope

        if (-not $CveId) {
            return [HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Error: cveId is required' }
            }
        }

        $CveExceptionsTable = Get-CIPPTable -TableName 'CveExceptions'
        $CveCacheTable      = Get-CIPPTable -TableName 'CveCache'

        $ExceptionsToRemove = switch ($RemoveScope) {
            'CurrentTenant' {
                if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
                    throw "Current tenant must be selected"
                }
                @($TenantFilter)
            }
            'AllAffected' {
                $AllExceptions = Get-CIPPAzDataTableEntity @CveExceptionsTable -Filter "PartitionKey eq '$CveId'"
                @($AllExceptions | Where-Object { $_.RowKey -ne 'ALL' } | Select-Object -ExpandProperty RowKey)
            }
            'Global' {
                @('ALL')
            }
            default {
                if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
                    @($TenantFilter)
                } else {
                    throw "removeScope must be specified when no tenant is selected"
                }
            }
        }

        $RemovedCount = 0

        foreach ($TenantId in $ExceptionsToRemove) {
            $ExceptionEntity = Get-CIPPAzDataTableEntity @CveExceptionsTable -Filter "PartitionKey eq '$CveId' and RowKey eq '$TenantId'"

            if ($ExceptionEntity) {
                Remove-AzDataTableEntity @CveExceptionsTable -Entity $ExceptionEntity -Force
                $RemovedCount++

                $CacheFilter = if ($TenantId -eq 'ALL') {
                    "PartitionKey eq '$CveId'"
                } else {
                    "PartitionKey eq '$CveId' and customerId eq '$TenantId'"
                }

                $CacheEntries = Get-CIPPAzDataTableEntity @CveCacheTable -Filter $CacheFilter

                foreach ($CacheEntry in $CacheEntries) {
                    $RemainingExceptions = Get-CIPPAzDataTableEntity @CveExceptionsTable -Filter "PartitionKey eq '$CveId' and (RowKey eq 'ALL' or RowKey eq '$($CacheEntry.customerId)')"

                    if (-not $RemainingExceptions) {
                        $CacheEntry.hasException    = $false
                        $CacheEntry.exceptionSource = ''
                    } else {
                        $CacheEntry.exceptionSource = ($RemainingExceptions | Select-Object -ExpandProperty source -Unique) -join '/'
                    }

                    Add-CIPPAzDataTableEntity @CveCacheTable -Entity $CacheEntry -Force
                }
            }
        }

        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Removed $RemovedCount CVE exception(s) for $CveId" -sev 'Info'

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @{ Results = "Successfully removed $RemovedCount exception(s) for CVE $CveId" }
        }

    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Failed to remove CVE exception: $($ErrorMessage.NormalizedError)" -sev 'Error' -LogData $ErrorMessage
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{ Results = "Failed to remove exception: $($ErrorMessage.NormalizedError)" }
        }
    }
}
