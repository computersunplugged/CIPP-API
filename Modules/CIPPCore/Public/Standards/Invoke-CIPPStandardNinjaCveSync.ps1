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

    param(
        $Tenant,
        $Settings
    )

    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Starting Ninja CVE Sync standard. Raw Settings: $($Settings | ConvertTo-Json -Depth 10)" -Sev 'Info'

    # ============================
    # 1. VALIDATE INPUTS
    # ============================

    $ScanGroupId = $Settings.ScanGroupId
    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Resolved ScanGroupId from Settings: '$ScanGroupId'" -Sev 'Debug'

    if ([string]::IsNullOrWhiteSpace($ScanGroupId)) {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Scan Group ID provided in standard settings" -Sev 'Error'
        throw "Scan Group ID must be configured in the Standard settings."
    }

    try {
        # ============================
        # 2. QUERY DEFENDER TVM
        # ============================
        $GraphUri   = "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?`$top=999"
        $GraphScope = "https://api.securitycenter.microsoft.com/.default"

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Pulling Defender TVM data. Tenant: $Tenant, URI: $GraphUri, Scope: $GraphScope" -Sev 'Debug'

        $Vulns = New-GraphGetRequest `
            -tenantid $Tenant `
            -uri $GraphUri `
            -scope $GraphScope

        if ($null -eq $Vulns) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "New-GraphGetRequest returned \$null for vulnerabilities" -Sev 'Warning'
        } else {
            $vulnCount = ($Vulns | Measure-Object).Count
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "New-GraphGetRequest returned $vulnCount vulnerability records" -Sev 'Info'

            # Log a small sample so we can see the structure
            $SampleVulns = $Vulns | Select-Object -First 3
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Sample Defender TVM records (first 3): $($SampleVulns | ConvertTo-Json -Depth 5)" -Sev 'Debug'
        }

        if (-not $Vulns) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No vulnerability data returned from Defender – proceeding with empty array" -Sev 'Warning'
            $Vulns = @()
        }

        # ============================
        # 3. GROUP + FORMAT FOR CSV
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

        $rowCount = $CsvRows.Count
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "CSV transformation complete. Total rows: $rowCount" -Sev 'Info'

        if ($rowCount -gt 0) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Sample CSV row: $($CsvRows[0] | ConvertTo-Json -Depth 5)" -Sev 'Debug'
        }

        if ($CsvRows.Count -eq 0) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No CVEs found to upload for this tenant" -Sev 'Info'

            if ($Settings.report) {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Settings.report is enabled – writing 'No CVEs detected' to compare field" -Sev 'Debug'
                Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue "No CVEs detected" -TenantFilter $Tenant
            }
            return
        }

        # Build CSV in memory
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Building CSV string from rows" -Sev 'Debug'
        $CsvContent = $CsvRows | ConvertTo-Csv -NoTypeInformation | Out-String

        # Log just the header + first data line for sanity
        $CsvLines = $CsvContent -split "`r?`n"
        $CsvPreview = ($CsvLines | Select-Object -First 3) -join "`n"
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "CSV preview (first 3 lines):`n$CsvPreview" -Sev 'Debug'

        $CsvBytes = [System.Text.Encoding]::UTF8.GetBytes($CsvContent)
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "CSV byte length: $($CsvBytes.Length)" -Sev 'Debug'

        # ============================
        # 4. GET NINJA CONFIG + TOKEN
        # ============================

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne configuration from Extensionsconfig table" -Sev 'Debug'

        $Table = Get-CIPPTable -TableName Extensionsconfig
        $RawConfigEntities = Get-CIPPAzDataTableEntity @Table

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Extensionsconfig entities count: $(( $RawConfigEntities | Measure-Object ).Count)" -Sev 'Debug'

        $Configuration = ($RawConfigEntities.config | ConvertFrom-Json).NinjaOne

        if ($null -eq $Configuration) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "NinjaOne configuration object is null after conversion from Extensionsconfig" -Sev 'Error'
        } else {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Resolved NinjaOne configuration: Instance='$($Configuration.Instance)', ClientId='$($Configuration.ClientId)'" -Sev 'Info'
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne API token using Get-NinjaOneToken -Configuration" -Sev 'Debug'

        $TokenObject = Get-NinjaOneToken -Configuration $Configuration

        if ($null -eq $TokenObject) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Get-NinjaOneToken returned \$null" -Sev 'Error'
            throw "Get-NinjaOneToken returned null"
        }

        # Do NOT log token value itself (security), just shape and presence.
        $hasAccessToken = [bool]$TokenObject.access_token
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Token object received. Has access_token: $hasAccessToken; Raw token object shape: $($TokenObject | Get-Member | Select-Object -ExpandProperty Name -Unique -ErrorAction SilentlyContinue -OutVariable +null | Out-String)" -Sev 'Debug'

        if (-not $TokenObject.access_token) {
            throw "Failed to retrieve NinjaOne access token"
        }

        $Headers = @{
            "Authorization" = "Bearer $($TokenObject.access_token)"
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Prepared HTTP headers for NinjaOne request (Authorization header present: $($Headers.ContainsKey('Authorization')))" -Sev 'Debug'

        # ============================
        # 5. UPLOAD FILE TO NINJAONE
        # ============================

        $UploadUri = "https://$($Configuration.Instance)/api/v2/vulnerability/scan-groups/$ScanGroupId/upload"

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "NinjaOne upload URI: $UploadUri" -Sev 'Info'
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Uploading CVE CSV to NinjaOne (ScanGroup: $ScanGroupId)" -Sev 'Info'

        try {
            $FormBody = @{
                file = [System.IO.MemoryStream]::new($CsvBytes)
            }

            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Form body prepared. MemoryStream length: $($FormBody.file.Length)" -Sev 'Debug'

            $Response = Invoke-RestMethod -Method Post -Uri $UploadUri -Headers $Headers -ContentType "multipart/form-data" -Form $FormBody

            if ($null -eq $Response) {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Invoke-RestMethod returned null response" -Sev 'Warning'
            } else {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "NinjaOne upload response (raw): $($Response | ConvertTo-Json -Depth 10)" -Sev 'Debug'
            }

            # If Ninja returns a 'status' property, log it explicitly
            if ($Response.PSObject.Properties.Name -contains 'status') {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload complete. NinjaOne response status: $($Response.status)" -Sev 'Info'
            } else {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload complete. NinjaOne response has no 'status' property." -Sev 'Info'
            }
        } catch {
            $UploadError = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Invoke-RestMethod upload failed. ErrorDetails: $UploadError" -Sev 'Error'
            throw $_
        }

        # ============================
        # 6. REPORT MODE
        # ============================
        if ($Settings.report) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Report mode enabled – recording uploaded row count: $($CsvRows.Count)" -Sev 'Debug'
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue "Uploaded $($CsvRows.Count) CVEs" -TenantFilter $Tenant
        }

        # ============================
        # 7. ALERT MODE
        # ============================
        if ($Settings.alert) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Alert mode enabled – writing alert about uploaded CVEs to NinjaOne ScanGroup $ScanGroupId" -Sev 'Debug'
            Write-StandardsAlert -message "Uploaded $($CsvRows.Count) CVEs to NinjaOne scan group $ScanGroupId" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync standard completed successfully" -Sev 'Info'

    } catch {
        $RawMessage = if ($_.Exception.Message) { $_.Exception.Message } else { "$_" }
        $ErrorMessage = Get-NormalizedError -Message $RawMessage

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync failed. Raw error: $RawMessage" -Sev 'Error'
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync failed (normalized): $ErrorMessage" -Sev 'Error'

        throw $ErrorMessage
    }
}
