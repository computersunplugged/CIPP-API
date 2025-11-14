function Invoke-CIPPStandardNinjaCveSync {
    <#
    .FUNCTIONALITY
        Standard
    .COMPONENT
        (APIName) NinjaCveSync
    .SYNOPSIS
        (Label) Sync Defender TVM CVEs to NinjaOne
    .DESCRIPTION
        (Helptext) Pulls Defender Threat & Vulnerability Management (TVM) vulnerabilities for the tenant and uploads them into a NinjaOne vulnerability scan group as a CSV.
        (DocsDescription) This standard queries Microsoft Defender TVM for software vulnerabilities affecting devices in the tenant, converts the results into a NinjaOne-compatible CSV, and uploads them to a configured NinjaOne vulnerability scan group. Use this to keep NinjaOne’s vulnerability view aligned with Defender TVM.
    .NOTES
        CAT
            Integrations
        TAG
            {"Security","NinjaOne","Vulnerability Management"}
        DISABLEDFEATURES
            {"report":false,"warn":false,"remediate":false}
        EXECUTIVETEXT
            Automatically synchronizes Microsoft Defender TVM vulnerabilities into NinjaOne, so your RMM platform reflects the real security posture of each tenant for easier remediation and reporting.
        ADDEDCOMPONENT
            {"type":"textField","name":"standards.NinjaCveSync.InstanceHost","label":"NinjaOne Instance Host (e.g. app.ninjarmm.com)","required":true}
            {"type":"textField","name":"standards.NinjaCveSync.ScanGroupId","label":"NinjaOne Scan Group ID","required":true}
        IMPACT
            Low Impact
        ADDEDDATE
            2025-11-14
        RECOMMENDEDBY
            {"CIPP"}
        UPDATECOMMENTBLOCK
            Run Tools\Update-StandardsComments.ps1 after editing this header.
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>

    [CmdletBinding()]
    param(
        $Tenant,
        $Settings
    )

    Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: starting for tenant $Tenant" -sev Info

    # =========================================
    # 0. READ & VALIDATE STANDARD SETTINGS
    # =========================================

    $InstanceHost = $Settings.InstanceHost
    $ScanGroupId  = $Settings.ScanGroupId

    if ([string]::IsNullOrWhiteSpace($InstanceHost)) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: InstanceHost not configured in standard settings – skipping." -sev Error
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($ScanGroupId)) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: ScanGroupId not configured in standard settings – skipping." -sev Error
        return $false
    }

    try {
        # =========================================
        # 1. QUERY DEFENDER TVM FOR THIS TENANT
        # =========================================

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: querying Defender TVM vulnerabilities" -sev Debug

        $tvmResults = New-GraphGetRequest `
            -tenantid $Tenant `
            -uri "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?`$top=999" `
            -scope 'https://api.securitycenter.microsoft.com/.default'

        if (-not $tvmResults) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: Defender TVM returned no data" -sev Warning

            if ($Settings.report) {
                Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue 'No Defender TVM data returned' -TenantFilter $Tenant
            }
            return $true
        }

        # Normalize to array
        $tvmArray = @($tvmResults)

        # Build rows: deviceIdentifier + cveId
        $csvRows = foreach ($row in $tvmArray) {
            if (-not $row.cveId) { continue }
            if (-not $row.deviceName) { continue }

            [PSCustomObject]@{
                deviceIdentifier = $row.deviceName
                cveId            = $row.cveId
            }
        }

        if (-not $csvRows -or $csvRows.Count -eq 0) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: no CVEs found to upload for this tenant" -sev Info

            if ($Settings.report) {
                Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue 'No CVEs found for this tenant' -TenantFilter $Tenant
            }
            return $true
        }

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: preparing CSV for $($csvRows.Count) CVE records" -sev Debug

        # =========================================
        # 2. BUILD CSV IN MEMORY
        # =========================================

        $csvString = $csvRows | ConvertTo-Csv -NoTypeInformation
        $csvText   = $csvString -join [Environment]::NewLine
        $csvBytes  = [System.Text.Encoding]::UTF8.GetBytes($csvText)

        # =========================================
        # 3. READ NINJA CONFIG (CLIENT ID) & SECRET
        # =========================================

        $ninjaSettingsTable = Get-CIPPTable -TableName NinjaOneSettings
        $ninjaSettings      = Get-AzDataTableEntity @ninjaSettingsTable

        if (-not $ninjaSettings) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: NinjaOneSettings table is empty – integration not configured." -sev Error
            return $false
        }

        # Use the first NinjaOneSettings row (typical CIPP deployment has one)
        $ninjaConfig = $ninjaSettings | Select-Object -First 1

        $ClientId = $ninjaConfig.ClientId
        if ([string]::IsNullOrWhiteSpace($ClientId)) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: ClientId missing in NinjaOneSettings – cannot request token." -sev Error
            return $false
        }

        $ClientSecret = Get-ExtensionAPIKey -Extension 'NinjaOne'
        if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: NinjaOne extension API key (client secret) is empty – cannot request token." -sev Error
            return $false
        }

        # =========================================
        # 4. REQUEST NINJAONE TOKEN USING INSTANCE FROM SETTINGS
        # =========================================

        $tokenUri = "https://$InstanceHost/ws/oauth/token"

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: requesting NinjaOne token from $tokenUri" -sev Debug

        $tokenBody = @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'monitoring management'
        }

        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'

        if (-not $tokenResponse -or -not $tokenResponse.access_token) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: failed to obtain NinjaOne access token" -sev Error
            return $false
        }

        # =========================================
        # 5. UPLOAD CSV TO NINJAONE SCAN GROUP
        # =========================================

        $uploadUri = "https://$InstanceHost/v2/vulnerability/scan-groups/$ScanGroupId/upload"

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: uploading CSV to $uploadUri" -sev Info

        # Build multipart/form-data using .NET HttpClient
        $handler   = [System.Net.Http.HttpClientHandler]::new()
        $httpClient = [System.Net.Http.HttpClient]::new($handler)

        $httpClient.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $tokenResponse.access_token)

        $content = [System.Net.Http.MultipartFormDataContent]::new()

        $fileContent = [System.Net.Http.ByteArrayContent]::new($csvBytes)
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/csv")

        # name "file" matches Ninja's API contract; filename is arbitrary but helpful
        $content.Add($fileContent, "file", "defender-tvm-$Tenant.csv")

        $response = $httpClient.PostAsync($uploadUri, $content).Result

        $responseBody = $response.Content.ReadAsStringAsync().Result

        if (-not $response.IsSuccessStatusCode) {
            $msg = "NinjaCveSync: NinjaOne upload failed with status code $($response.StatusCode). Body: $responseBody"
            Write-LogMessage -API 'Standards' -tenant $Tenant -message $msg -sev Error
            throw $msg
        }

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: upload succeeded with status code $($response.StatusCode)" -sev Info

        # =========================================
        # 6. REPORT / ALERT IN CIPP
        # =========================================

        if ($Settings.report) {
            Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue "Uploaded $($csvRows.Count) CVE rows to NinjaOne scan group $ScanGroupId" -TenantFilter $Tenant
        }

        if ($Settings.alert) {
            Write-StandardsAlert -message "Uploaded $($csvRows.Count) CVE rows to NinjaOne scan group $ScanGroupId on instance $InstanceHost" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
        }

        return $true
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) {
            Get-NormalizedError -Message $_.ErrorDetails.Message
        } else {
            $_.Exception.Message
        }

        Write-LogMessage -API 'Standards' -tenant $Tenant -message "NinjaCveSync: failed with error: $ErrorMessage" -sev Error
        throw $ErrorMessage
    }
}
