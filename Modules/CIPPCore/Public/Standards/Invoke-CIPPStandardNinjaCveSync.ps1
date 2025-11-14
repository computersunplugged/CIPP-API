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
            {"type":"textField","name":"standards.NinjaCveSync.InstanceHost","label":"NinjaOne Instance Host (e.g. app.ninjarmm.com or oc.ninjaone.com)","required":false}
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

    param(
        $Tenant,
        $Settings
    )

    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Starting Ninja CVE Sync standard" -Sev 'Info'

    # ============================
    # 0. Resolve instance + inputs
    # ============================
    $ScanGroupId = $Settings.ScanGroupId
    if ([string]::IsNullOrWhiteSpace($ScanGroupId)) {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Scan Group ID provided in standard settings" -Sev 'Error'
        throw "Scan Group ID must be configured in the Standard settings."
    }

    # Instance host (priority: Standard setting → org mapping → default app.ninjarmm.com)
    $InstanceHost = $Settings.InstanceHost
    if (-not $InstanceHost) {
        try {
            $orgMap = Get-NinjaOneOrgMapping -ErrorAction Stop
            if ($orgMap -and $orgMap.InstanceHost) { $InstanceHost = $orgMap.InstanceHost }
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($InstanceHost)) { $InstanceHost = 'app.ninjarmm.com' }

    # Normalise to full https://host form
    if ($InstanceHost -notmatch '^https?://') { $InstanceHost = "https://$InstanceHost" }

    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Using NinjaOne instance: $InstanceHost" -Sev 'Debug'

    try {
        # ============================
        # 1. QUERY DEFENDER TVM
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
        # 2. FORMAT FOR CSV
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Transforming CVE data into Ninja CSV format" -Sev 'Debug'

        $CsvRows = @()
        foreach ($item in $Vulns) {
            if (-not $item.cveId) { continue }
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

        $CsvContent = $CsvRows | ConvertTo-Csv -NoTypeInformation | Out-String
        $CsvBytes   = [System.Text.Encoding]::UTF8.GetBytes($CsvContent)

        # ============================
        # 3. GET NINJA TOKEN
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne API token" -Sev 'Debug'
        $TokenObject = Get-NinjaOneToken
        if (-not $TokenObject.access_token) {
            throw "Failed to retrieve NinjaOne access token"
        }
        $Headers = @{ "Authorization" = "Bearer $($TokenObject.access_token)" }

        # ============================
        # 4. UPLOAD FILE TO NINJAONE
        # ============================
        $UploadUri = "$InstanceHost/v2/vulnerability/scan-groups/$ScanGroupId/upload"
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Uploading CVE CSV to NinjaOne (ScanGroup: $ScanGroupId) via $UploadUri" -Sev 'Info'

        $Response = Invoke-RestMethod -Method Post -Uri $UploadUri -Headers $Headers -ContentType "multipart/form-data" -Form @{
            file = [System.IO.MemoryStream]::new($CsvBytes)
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload complete. NinjaOne response: $($Response.status)" -Sev 'Info'

        # ============================
        # 5. REPORT / ALERT
        # ============================
        if ($Settings.report) {
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue "Uploaded $($CsvRows.Count) CVEs" -TenantFilter $Tenant
        }
        if ($Settings.alert) {
            Write-StandardsAlert -message "Uploaded $($CsvRows.Count) CVEs to NinjaOne scan group $ScanGroupId" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
        }

    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync failed: $ErrorMessage" -Sev 'Error'
        throw $ErrorMessage
    }
}
