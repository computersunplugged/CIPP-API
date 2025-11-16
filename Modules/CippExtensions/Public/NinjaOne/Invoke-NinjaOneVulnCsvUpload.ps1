function Invoke-NinjaOneVulnCsvUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][byte[]]$CsvBytes,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $boundary = [System.Guid]::NewGuid().ToString()
    $nl = "`r`n"
    $mem = New-Object System.IO.MemoryStream
    $wr  = New-Object System.IO.StreamWriter($mem, [System.Text.Encoding]::UTF8)

    try {
        $wr.Write("--$boundary$nl")
        $wr.Write("Content-Disposition: form-data; name=`"file`"; filename=`"cve.csv`"$nl")
        $wr.Write("Content-Type: text/csv$nl$nl")
        $wr.Flush()

        $mem.Write($CsvBytes, 0, $CsvBytes.Length)

        $wr.Write("$nl--$boundary--$nl")
        $wr.Flush()
        $mem.Position = 0

        Write-LogMessage -API 'NinjaOne' -message "Uploading CVE CSV to $Uri" -Sev 'Info'

        $resp = Invoke-RestMethod -Method POST -Uri $Uri `
            -Headers $Headers `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $mem

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
