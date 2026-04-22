function Invoke-NinjaOneVulnCsvUpload {
    <#
    .SYNOPSIS
        Upload CVE CSV to NinjaOne vulnerability scan group via multipart POST.
    .PARAMETER Uri
        Full NinjaOne API upload URI including scan group ID.
    .PARAMETER CsvBytes
        UTF-8 encoded CSV payload as a byte array.
    .PARAMETER Headers
        Hashtable of HTTP headers including Authorization bearer token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][byte[]]$CsvBytes,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $Boundary = [System.Guid]::NewGuid().ToString()
    $LF       = "`r`n"

    $BodyLines = @(
    "--$Boundary"
    'Content-Disposition: form-data; name="csv"; filename="cve.csv"'
    'Content-Type: text/csv'
    ''
    )

    $HeaderText  = $BodyLines -join $LF
    $HeaderBytes = [System.Text.Encoding]::UTF8.GetBytes($HeaderText + $LF)

    $TrailerText  = "$LF--$Boundary--$LF"
    $TrailerBytes = [System.Text.Encoding]::UTF8.GetBytes($TrailerText)

    $Mem = [System.IO.MemoryStream]::new()
    try {
        $Mem.Write($HeaderBytes, 0, $HeaderBytes.Length)
        $Mem.Write($CsvBytes,    0, $CsvBytes.Length)
        $Mem.Write($TrailerBytes, 0, $TrailerBytes.Length)
        $Mem.Position = 0

        Write-LogMessage -API 'NinjaOne' -message "Uploading CVE CSV to NinjaOne ($($CsvBytes.Length) bytes)" -sev 'Debug'

        $Resp = Invoke-RestMethod -Method POST -Uri $Uri `
            -Headers $Headers `
            -ContentType "multipart/form-data; boundary=$Boundary" `
            -Body $Mem `
            -ErrorAction Stop

        return $Resp
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'NinjaOne' -message "CSV upload failed: $($ErrorMessage.NormalizedError)" -sev 'Error' -LogData $ErrorMessage
        throw
    } finally {
        $Mem.Dispose()
    }
}
