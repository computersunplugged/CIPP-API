function Invoke-NinjaOneVulnCsvUpload {
    <#
    .SYNOPSIS
        Upload a CVE CSV to an existing NinjaOne vulnerability scan group.
    .DESCRIPTION
        Forms a multipart/form-data request with part name 'file' and posts to:
          https://<Instance>/api/v2/vulnerability/scan-groups/{scanGroupId}/upload
    .PARAMETER Instance
        NinjaOne API host (e.g., 'api.ninjarmm.com'). Taken from $Configuration.Instance in CIPP.
    .PARAMETER ScanGroupId
        Target scan group id.
    .PARAMETER CsvBytes
        UTF-8 byte[] of the CSV payload.
    .PARAMETER Headers
        Hashtable of HTTP headers; must include Authorization: Bearer <token>.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Instance,
        [Parameter(Mandatory)][string]$ScanGroupId,
        [Parameter(Mandatory)][byte[]]$CsvBytes,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $boundary = [System.Guid]::NewGuid().ToString()
    $nl = "`r`n"
    $mem = New-Object System.IO.MemoryStream
    $wr  = New-Object System.IO.StreamWriter($mem, [System.Text.Encoding]::UTF8)

    try {
        # Part header
        $wr.Write("--$boundary$nl")
        $wr.Write("Content-Disposition: form-data; name="file"; filename="cve.csv"$nl")
        $wr.Write("Content-Type: text/csv$nl$nl")
        $wr.Flush()

        # CSV content
        $mem.Write($CsvBytes, 0, $CsvBytes.Length)

        # Trailer
        $wr.Write("$nl--$boundary--$nl")
        $wr.Flush()
        $mem.Position = 0

        $uri = "https://{0}/api/v2/vulnerability/scan-groups/{1}/upload" -f $Instance, $ScanGroupId
        $contentType = "multipart/form-data; boundary=$boundary"

        Write-LogMessage -API 'NinjaOne' -message "Uploading CVE CSV to scan-group $ScanGroupId at $Instance" -Sev 'Info'
        $resp = Invoke-RestMethod -Method POST -Uri $uri -Headers $Headers -ContentType $contentType -Body $mem
        return $resp
    }
    catch {
        Write-LogMessage -API 'NinjaOne' -message ("CSV upload failed: {0}" -f $_.Exception.Message) -Sev 'Error'
        throw
    }
    finally {
        $wr.Dispose()
        $mem.Dispose()
    }
}
