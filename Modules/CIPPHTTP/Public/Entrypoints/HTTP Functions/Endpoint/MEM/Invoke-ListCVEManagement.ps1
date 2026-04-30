function Invoke-ListCVEManagement {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Endpoint.Security.Read
    #>
           Write-LogMessage -API 'ListCVEManagement' -tenant $TenantFilter -message "Top of the page" -sev 'info'
       Write-Host "Host instead"
    <#
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.tenantFilter
    $UseReportDB = $Request.Query.UseReportDB

       Write-LogMessage -API 'ListCVEManagement' -tenant $TenantFilter -message "Top of the page" -sev 'info'
       Write-Host "Host instead"
    try {
        $GraphRequest = Get-CIPPMailboxesReport -TenantFilter $TenantFilter -ErrorAction Stop
        $StatusCode = [HttpStatusCode]::OK
        Write-LogMessage -API 'ListCVEManagement' -tenant $TenantFilter -message "running cve report" -sev 'info'
    } catch {
        Write-Host "Error retrieving CVEs from report database: $($_.Exception.Message)"
        $StatusCode = [HttpStatusCode]::InternalServerError
        $GraphRequest = $_.Exception.Message
    }

    return ([HttpResponseContext]@{
                    StatusCode = $StatusCode
                    Body       = @($GraphRequest)
                    Write-LogMessage -API 'ListCVEManagement' -tenant $TenantFilter -message "$GraphRequest" -sev 'info'
    })
#>
