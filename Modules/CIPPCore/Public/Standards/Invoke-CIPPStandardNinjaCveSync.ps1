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
            {"type":"textField","name":"standards.NinjaCveSync.ScanGroupName","label":"NinjaOne Scan Group Name","required":true}
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
    # 1. VALIDATE INPUTS & GET CONFIG
    # ============================
    $ScanGroupInput = $Settings.ScanGroupName
    if ([string]::IsNullOrWhiteSpace($ScanGroupInput)) {
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "No Scan Group name provided in standard settings" -Sev 'Error'
        throw "Scan Group name must be configured in the Standard settings."
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

        # ============================
        # 4. RESOLVE SCAN GROUP BY NAME
        # ============================
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Fetching scan groups from NinjaOne to resolve '$ScanGroupInput'" -Sev 'Debug'
        
        $ScanGroupsUri = "$NinjaBaseUrl/vulnerability/scan-groups"
        
        try {
            $ScanGroups = Invoke-RestMethod -Method Get -Uri $ScanGroupsUri -Headers $Headers -TimeoutSec 30
        }
        catch {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Failed to retrieve scan groups: $($_.Exception.Message)" -Sev 'Error'
            throw "Failed to retrieve scan groups from NinjaOne: $($_.Exception.Message)"
        }

        if (-not $ScanGroups) {
            throw "Failed to retrieve scan groups from NinjaOne. Response was empty."
        }

        # Treat input as groupName (name-based resolution)
        $ResolvedScanGroup = $ScanGroups | Where-Object { $_.groupName -eq $ScanGroupInput }
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "ScanGroup input '$ScanGroupInput' treated as groupName" -Sev 'Debug'

        if (-not $ResolvedScanGroup) {
            $Available = ($ScanGroups | Select-Object -First 10 | ForEach-Object { "$($_.id):$($_.groupName)" }) -join ', '
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Unable to resolve scan group '$ScanGroupInput'. First few available: $Available" -Sev 'Error'
            throw "Scan group '$ScanGroupInput' could not be resolved by groupName."
        }

        $ResolvedScanGroupId = $ResolvedScanGroup.id
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Resolved scan group '$ScanGroupInput' to ID $ResolvedScanGroupId (name: $($ResolvedScanGroup.groupName))" -Sev 'Info'

        # ============================
        # 5. TRANSFORM TO CSV ROWS
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
        # 6. BUILD CSV BYTES (using helper function)
        # ============================
        $CsvBytes = New-VulnCsvBytes -Rows $CsvRows -Headers @('deviceIdentifier', 'cveId')
        
        if (-not $CsvBytes -or $CsvBytes.Length -eq 0) {
            throw "Failed to generate CSV bytes from vulnerability data"
        }
        
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Generated CSV payload: $($CsvBytes.Length) bytes" -Sev 'Debug'

        # Preview first 5 lines of the CSV
        try {
            $CsvText = [System.Text.Encoding]::UTF8.GetString($CsvBytes)
            $Lines   = $CsvText -split "`n"
            $Max     = [Math]::Min(5, $Lines.Count)
            $Preview = $Lines[0..($Max - 1)]
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -Sev 'Debug' -message ("CSV Preview:`n" + ($Preview -join "`n"))
        }
        catch {
            Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -Sev 'Warning' -message "CSV preview failed: $($_.Exception.Message)"
        }

        # ============================
        # 7. UPLOAD TO NINJAONE (using helper function)
        # ============================
        # Build the full upload URI once and pass it to the helper
        $UploadUri = "$NinjaBaseUrl/vulnerability/scan-groups/$ResolvedScanGroupId/upload"
        Write-LogMessage -API 'NinjaCveSync' -tenant $Tenant -message "Uploading CVE CSV to NinjaOne (ScanGroupId: $ResolvedScanGroupId, Uri: $UploadUri)" -Sev 'Info'

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
        # 8. REPORT MODE
        # ============================
        if ($Settings.report) {
            $ReportMessage = "Uploaded $($CsvRows.Count) CVEs to scan group '$($ResolvedScanGroup.groupName)'"
            Set-CIPPStandardsCompareField -FieldName "standards.NinjaCveSync" -FieldValue $ReportMessage -TenantFilter $Tenant
        }

        # ============================
        # 9. ALERT MODE
        # ============================
        if ($Settings.alert) {
            Write-StandardsAlert -message "Uploaded $($CsvRows.Count) CVEs to NinjaOne scan group '$($ResolvedScanGroup.groupName)' (ID: $ResolvedScanGroupId)" -tenant $Tenant -standardName 'NinjaCveSync' -standardId $Settings.standardId
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
