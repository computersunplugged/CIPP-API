function Invoke-NinjaOneVulnCsvUpload {
    <#
    .SYNOPSIS
        Upload a CSV to a NinjaOne vulnerability scan group.
    .DESCRIPTION
        Wraps POST /v2/vulnerability/scan-groups/{scan-group-id}/upload (multipart/form-data).
        Accepts either prebuilt $Headers/$BaseUri from your existing NinjaOne helpers
        or lets the caller supply them directly.
    .PARAMETER ScanGroupId
        Target scan group ID (integer-as-string is fine).
    .PARAMETER CsvBytes
        Byte[] of the CSV file content (UTF-8 without BOM recommended).
    .PARAMETER BaseUri
        Base API URI for NinjaOne (e.g., https://api.ninjaone.com or your region base).
    .PARAMETER Headers
        Hashtable of HTTP headers (must include Authorization and Content-Type will be set here).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScanGroupId,
        [Parameter(Mandatory)] [byte[]] $CsvBytes,
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [hashtable] $Headers
    )

    # Build multipart body
    $boundary = [System.Guid]::NewGuid().ToString()
    $nl       = "`r`n"
    $stream   = New-Object System.IO.MemoryStream
    $writer   = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)

    try {
        $writer.Write("--$boundary$nl")
        $writer.Write("Content-Disposition: form-data; name=`"file`"; filename=`"cve.csv`"$nl")
        $writer.Write("Content-Type: text/csv$nl$nl")
        $writer.Flush()
        $stream.Write($CsvBytes, 0, $CsvBytes.Length)
        $writer.Write("$nl--$boundary--$nl")
        $writer.Flush()
        $stream.Position = 0

        $uri = "$BaseUri/v2/vulnerability/scan-groups/$ScanGroupId/upload"

        # Clone headers so we can safely set content-type
        $reqHeaders = @{}
        foreach ($k in $Headers.Keys) { $reqHeaders[$k] = $Headers[$k] }

        $contentType = "multipart/form-data; boundary=$boundary"

        Write-LogMessage -API 'NinjaOne' -message "Uploading CSV to scan-group $ScanGroupId" -sev 'Info'
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $reqHeaders -ContentType $contentType -Body $stream

        Write-LogMessage -API 'NinjaOne' -message ("Upload accepted. Status: {0}; RecordsProcessed: {1}" -f $resp.status, $resp.recordsProcessed) -sev 'Info'
        return $resp
    }
    catch {
        $msg = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'NinjaOne' -message "CSV upload failed for scan-group $ScanGroupId: $msg" -sev 'Error'
        throw
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}