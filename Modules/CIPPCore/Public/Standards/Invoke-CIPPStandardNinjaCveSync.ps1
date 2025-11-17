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

    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Starting Ninja CVE Sync standard V0.8" -Sev 'Info'

    # ============================
    # 1. VALIDATE INPUTS & GET CONFIG
    # ============================
    $ScanGroupInput = $Settings.ScanGroupId
    if ([string]::IsNullOrWhiteSpace($ScanGroupInput)) {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Scan Group ID/name provided in standard settings" -Sev 'Error'
        throw "Scan Group ID (or name) must be configured in the Standard settings."
    }

    # Get NinjaOne configuration from Azure Table Storage
    try {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne configuration from Extensions table" -Sev 'Debug'
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $ConfigEntity = Get-AzDataTableEntity @Table
        
        if (-not $ConfigEntity -or -not $ConfigEntity.config) {
            throw "No configuration found in Extensionsconfig table"
        }
        
        $Configuration = ($ConfigEntity.config | ConvertFrom-Json).NinjaOne
        
        if (-not $Configuration -or -not $Configuration.Instance) {
            throw "NinjaOne configuration is missing or incomplete"
        }
        
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieved NinjaOne config for instance: $($Configuration.Instance)" -Sev 'Debug'
    }
    catch {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Failed to retrieve NinjaOne configuration: $($_.Exception.Message)" -Sev 'Error'
        throw "Failed to retrieve NinjaOne configuration: $($_.Exception.Message)"
    }

    try {
        # ============================
        # 2. QUERY DEFENDER TVM (using helper function)
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Pulling Defender TVM data via Get-DefenderTvmRaw" -Sev 'Debug'
        
        $AllVulns = Get-DefenderTvmRaw -TenantId $Tenant -MaxPages 0
        
        if (-not $AllVulns) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No vulnerability data returned from Defender TVM" -Sev 'Warning'
            $AllVulns = @()
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieved $($AllVulns.Count) vulnerabilities from Defender TVM" -Sev 'Info'

        # ============================
        # 3. GET NINJA TOKEN WITH CONFIG
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Retrieving NinjaOne API token" -Sev 'Debug'
        
        $Token = Get-NinjaOneToken -configuration $Configuration
        
        if (-not $Token -or -not $Token.access_token) {
            throw "Failed to retrieve NinjaOne access token"
        }
        
        $Headers = @{
            "Authorization" = "Bearer $($Token.access_token)"
        }
        
        # Build base API URL from configuration
        $NinjaBaseUrl = "https://$($Configuration.Instance)/api/v2"
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Using NinjaOne API base: $NinjaBaseUrl" -Sev 'Debug'
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Using scan group name: '$ScanGroupInput'" -Sev 'Info'

        # ============================
        # 4. TRANSFORM TO CSV ROWS
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Transforming CVE data into Ninja CSV format" -Sev 'Debug'
        $CsvRows = @()
        $SkippedCount = 0

        foreach ($item in $AllVulns) {
            # Validate required fields
            if ([string]::IsNullOrWhiteSpace($item.cveId) -or [string]::IsNullOrWhiteSpace($item.deviceName)) {
                $SkippedCount++
                continue
            }
            
            $CsvRows += [PSCustomObject]@{
                deviceIdentifier = $item.deviceName.Trim()
                cveId            = $item.cveId.Trim()
            }
        }

        if ($SkippedCount -gt 0) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Skipped $SkippedCount vulnerabilities due to missing deviceName or cveId" -Sev 'Warning'
        }

        if ($CsvRows.Count -eq 0) {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No valid CVEs found to upload for this tenant" -Sev 'Info'
            
            if ($Settings.report) {
                Set-CIPPStandardsCompareField -FieldName 'standards.NinjaCveSync' -FieldValue "No valid CVEs detected" -TenantFilter $Tenant
            }
            return
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Prepared $($CsvRows.Count) CVE rows for upload" -Sev 'Info'

        # ============================
        # 5. BUILD CSV BYTES (using helper function)
        # ============================
        $CsvBytes = New-VulnCsvBytes -Rows $CsvRows -Headers @('deviceIdentifier', 'cveId')
        
        if (-not $CsvBytes -or $CsvBytes.Length -eq 0) {
            throw "Failed to generate CSV bytes from vulnerability data"
        }
        
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Generated CSV payload: $($CsvBytes.Length) bytes" -Sev 'Info'

        # Preview first 5 lines of the CSV - ALWAYS log this at Info level for debugging
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "=== CSV PREVIEW START ===" -Sev 'Info'
        try {
            $CsvText = [System.Text.Encoding]::UTF8.GetString($CsvBytes)
            $Lines   = $CsvText -split "`r`n|`n"
            $Max     = [Math]::Min(5, $Lines.Count)
            
            for ($i = 0; $i -lt $Max; $i++) {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Line $($i + 1): $($Lines[$i])" -Sev 'Info'
            }
        }
        catch {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "CSV preview failed: $($_.Exception.Message)" -Sev 'Error'
        }
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "=== CSV PREVIEW END ===" -Sev 'Info'

        # ============================
        # 6. UPLOAD TO NINJAONE (using helper function)
        # ============================
        # Use the scan group name directly in the URL
        $UploadUri = "$NinjaBaseUrl/vulnerability/scan-groups/$ScanGroupInput/upload"
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Uploading CVE CSV to NinjaOne (ScanGroup: '$ScanGroupInput', Uri: $UploadUri)" -Sev 'Info'

        try {
            $Response = Invoke-NinjaOneVulnCsvUpload `
                -Uri $UploadUri `
                -CsvBytes $CsvBytes `
                -Headers $Headers
            
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload completed successfully" -Sev 'Info'
            
            # Log response if present
            if ($Response) {
                Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "NinjaOne response: $($Response | ConvertTo-Json -Compress)" -Sev 'Debug'
                
                # Check for common response patterns
                if ($Response.status -and $Response.status -ne "success") {
                    Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Upload may have issues. Response status: $($Response.status)" -Sev 'Warning'
                }
            }
        }
        catch {
            # Error already logged by helper function
            throw
        }

        # ============================
        # 7. REPORT MODE
        # ============================
        if ($Settings.report) {
            $ReportMessage = "Uploaded $($CsvRows.Count) CVEs to scan group '$ScanGroupInput'"
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue $ReportMessage -TenantFilter $Tenant
        }

        # ============================
        # 8. ALERT MODE
        # ============================
        if ($Settings.alert) {
            Write-StandardsAlert -message "Uploaded $($CsvRows.Count) CVEs to NinjaOne scan group '$ScanGroupInput'" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
        }

        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync completed successfully for $($CsvRows.Count) CVEs" -Sev 'Info'

    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Ninja CVE Sync failed: $ErrorMessage" -Sev 'Error'
        
        if ($Settings.report) {
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue "Failed: $ErrorMessage" -TenantFilter $Tenant
        }
        
        throw $ErrorMessage
    }
}

