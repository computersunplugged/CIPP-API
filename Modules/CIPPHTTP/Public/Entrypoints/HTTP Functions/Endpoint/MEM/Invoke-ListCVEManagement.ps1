function Invoke-ListCVEManagement {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Endpoint.Security.Read
    #>

    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.tenantFilter
    $UseReportDB = $Request.Query.UseReportDB

        $DefenderCapable = $false
        try {
            $DefenderCapable = Test-CIPPStandardLicense -StandardName 'DefenderLicenseCheck' -TenantFilter $TenantFilter -RequiredCapabilities @('DEFENDER_FOR_ENDPOINT_PLAN_1', 'DEFENDER_FOR_ENDPOINT_PLAN_2', 'DEFENDER_FOR_BUSINESS') -SkipLog
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Compliance license check failed: $($_.Exception.Message)" -sev Warning -LogData $ErrorMessage
        }

if ($DefenderCapable) {
    try {
        $GraphRequest = Get-CIPPCVEReport -TenantFilter $TenantFilter -ErrorAction Stop
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
    })
    Write-LogMessage -API 'ListCVEManagement' -tenant $TenantFilter -message "$GraphRequest" -sev 'info'
            } else {
            Write-Host "Skipping Defender data collection for $TenantFilter - no required license"
        }
}

