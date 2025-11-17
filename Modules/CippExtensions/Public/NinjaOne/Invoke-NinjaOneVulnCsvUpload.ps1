function Invoke-NinjaOneVulnCsvUpload {
    <#
    .SYNOPSIS
        Upload CVE CSV to NinjaOne vulnerability scan group
    .NOTES
        Version: 2.0
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][byte[]]$CsvBytes,
        [Parameter(Mandatory)][hashtable]$Headers
    )
    
    Write-LogMessage -API 'NinjaOne' -message "Helper Version 2.0 - Starting upload" -Sev 'Info'
    
    $boundary = [System.Guid]::NewGuid().ToString()
    $nl = "`r`n"
    $mem = New-Object System.IO.MemoryStream
    $wr  = New-Object System.IO.StreamWriter($mem, [System.Text.Encoding]::UTF8)
    
    try {
        # Build multipart form data with proper escaping
        $wr.Write("--$boundary$nl")
        
        # Use variable to avoid backtick escaping issues
        $contentDisposition = 'Content-Disposition: form-data; name="csv"; filename="cve.csv"'
        $wr.Write("$contentDisposition$nl")
        
        $wr.Write("Content-Type: text/csv$nl$nl")
        $wr.Flush()
        
        # Write CSV bytes
        $mem.Write($CsvBytes, 0, $CsvBytes.Length)
        
        # Write boundary trailer
        $wr.Write("$nl--$boundary--$nl")
        $wr.Flush()
        $mem.Position = 0
        
        Write-LogMessage -API 'NinjaOne' -message "Uploading CVE CSV to $Uri" -Sev 'Info'
        
        # Debug multipart body
        $debugBody = [System.Text.Encoding]::UTF8.GetString($mem.ToArray())
        Write-LogMessage -API 'NinjaOne' -message "Multipart body preview (first 500 chars): $($debugBody.Substring(0, [Math]::Min(500, $debugBody.Length)))" -Sev 'Info'
        $mem.Position = 0
        
        $resp = Invoke-RestMethod -Method POST -Uri $Uri `
            -Headers $Headers `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $mem
        
        Write-LogMessage -API 'NinjaOne' -message "Upload successful" -Sev 'Info'
        return $resp
    }
    catch {
        Write-LogMessage -API 'NinjaOne' -message "CSV upload failed: $($_.Exception.Message)" -Sev 'Error'
        throw
    }
    finally {
        if ($wr) { $wr.Dispose() }
        if ($mem) { $mem.Dispose() }
    }
}
