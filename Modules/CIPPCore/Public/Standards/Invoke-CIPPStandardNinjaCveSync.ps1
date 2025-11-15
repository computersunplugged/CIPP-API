function Invoke-CIPPStandardNinjaCveSync {
    <#
    .FUNCTIONALITY
        Entrypoint
    .COMPONENT
        (APIName) NinjaCveSync
    .SYNOPSIS
        (Label) Sync Defender CVEs to NinjaOne
    .DESCRIPTION
        (Helptext) Pulls Defender TVM vulnerabilities for each tenant and uploads them to a specified NinjaOne Scan Group.
        (DocsDescription) This standard queries Microsoft Defender Threat & Vulnerability Management (TVM) for all software vulnerabilities affecting devices in the tenant. Results are converted into a NinjaOne-compatible CSV and uploaded to the configured NinjaOne Scan Group.
    .NOTES
        CAT
            Global Standards
        TAG
            Security
        DISABLEDFEATURES
            {"report":true,"warn":true,"remediate":true}
        EXECUTIVETEXT
            Automatically synchronizes Microsoft Defender vulnerabilities into NinjaOne for unified alerting and remediation workflows, ensuring your RMM platform always reflects the real security posture of your clients.
        ADDEDCOMPONENT
            {"type":"textField","name":"standards.NinjaCveSync.ScanGroupId","label":"NinjaOne Scan Group ID","required":true}
        IMPACT
            Medium Impact
        ADDEDDATE
            2025-01-22
        RECOMMENDEDBY
            ["CIPP"]
        UPDATECOMMENTBLOCK
            Run Tools\Update-StandardsComments.ps1 after editing this header.
    #>

    [CmdletBinding()]
    param(
        $Tenant,
        $Settings
    )

    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Starting Ninja CVE Sync standard" -Sev 'Info'

    # ============================
    # 1. VALIDATE INPUTS
    # ============================

    $ScanGroupId = $Settings.ScanGroupId

    if ([string]::IsNullOrWhiteSpace($ScanGroupId)) {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Scan Group ID provided in standard settings" -Sev 'Error'
        throw "Scan Group ID must be configured in the Standard settings."
    }

    try {
        # ============================
        # 2. QUERY DEFENDER TVM
        # ============================

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Pulling Defender TVM data" -Sev 'Debug'

        $Vulns = New-GraphGetRequest `
            -tenantid $Tenant `
            -uri "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?`$top=999" `
            -scope "https://api.securitycenter.microsoft.com/.default"

        if (-not $Vulns) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No vulnerability data returned from Defender" -Sev 'Warning'
            $Vulns = @()
        }

        # ============================
        # 3. GROUP + FORMAT FOR CSV
        # ============================

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Transforming CVE data into Ninja CSV format" -Sev 'Debug'

        $CsvRows = @()

        foreach ($item in $Vulns) {
            if (-not $item.cveId) { continue }
            if (-not $item.deviceName) { continue }

            $CsvRows += [PSCustomObject]@{
                deviceIdentifier = $item.deviceName
                cveId            = $item.cveId
            }
        }

        if ($CsvRows.Count -eq 0) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No CVEs found to upload for this tenant" -Sev 'Info'

            if ($Settings.report) {
                Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue "No CVEs detected" -TenantFilter $Tenant
            }
            return
        }

        # Build CSV in memory
        $CsvContent = $CsvRows | ConvertTo-Csv -NoTypeInformation | Out-String
        $CsvBytes   = [System.Text.Encoding]::UTF8.GetBytes($CsvContent)

        # ============================
        # 4. LOAD NINJA CONFIG
        #    (same pattern as Invoke-NinjaOneTenantSync)
        # ============================

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Loading NinjaOne configuration from Extensionsconfig" -Sev 'Debug'

        $ExtensionsConfigTable = Get-CIPPTable -TableName Extensionsconfig
        $ExtConfigEntities     = Get-CIPPAzDataTableEntity @ExtensionsConfigTable

        if (-not $ExtConfigEntities) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Extensionsconfig entries found – NinjaOne integration not configured." -Sev 'Error'
            throw "NinjaOne integration is not configured in Extensionsconfig."
        }

        # 'config' is JSON; .NinjaOne matches the structure used elsewhere in CIPP
        $NinjaConfigJson = $ExtConfigEntities.config | Select-Object -First 1
        if (-not $NinjaConfigJson) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Extensionsconfig exists but NinjaOne config is missing." -Sev 'Error'
            throw "NinjaOne configuration missing from Extensionsconfig."
        }

        $Configuration = ($NinjaConfigJson | ConvertFrom-Json).NinjaOne

        if (-not $Configuration.Instance) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "NinjaOne config does not contain Instance." -Sev 'Error'
            throw "NinjaOne Instance is not configured."
        }

        # ============================
        # 5. GET NINJA TOKEN
        # ============================

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne API token for instance $($Configuration.Instance)" -Sev 'Debug'

        $TokenObject = Get-NinjaOneToken -Configuration $Configuration

        if (-not $TokenObject -or -not $TokenObject.access_token) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Failed to retrieve NinjaOne access token." -Sev 'Error'
            throw "Failed to retrieve NinjaOne access token. Check NinjaOne extension configuration."
        }

        $Headers = @{
            "Authorization" = "Bearer $($TokenObject.access_token)"
        }

        # ============================
        # 6. UPLOAD FILE TO NINJAONE
        # ============================

        # Follow same host usage as other Ninja integrations
        $UploadHost = $Configuration.Instance -replace '/ws',''
        $UploadUri  = "https://$UploadHost/api/v2/vulnerability/scan-groups/$ScanGroupId/upload"

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Uploading CVE CSV to NinjaOne (Host: $UploadHost, ScanGroup: $ScanGroupId)" -Sev 'Info'

        $Response = Invoke-RestMethod -Method Post -Uri $UploadUri -Headers $Headers -ContentType "multipart/form-data" -Form @{
            file = [System.IO.MemoryStream]::new($CsvBytes)
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload complete. NinjaOne response: $($Response.status)" -Sev 'Info'

        # ============================
        # 7. REPORT / ALERT
        # ============================

        if ($Settings.report) {
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue "Uploaded $($CsvRows.Count) CVEs" -TenantFilter $Tenant
        }

        if ($Settings.alert) {
            Write-StandardsAlert -message "Uploaded $($CsvRows.Count) CVEs to NinjaOne scan group $ScanGroupId on $UploadHost" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
        }

    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) {
            Get-NormalizedError -Message $_.ErrorDetails.Message
        } else {
            Get-NormalizedError -Message $_.Exception.Message
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync failed: $ErrorMessage" -Sev 'Error'
        throw $ErrorMessage
    }
}
