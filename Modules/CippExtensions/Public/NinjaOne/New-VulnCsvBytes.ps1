function New-VulnCsvBytes {
    [CmdletBinding()]
    param([object[]] $Rows,[string[]] $Headers)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(($Headers -join ','))
    foreach ($r in $Rows) {
        $cells = foreach ($h in $Headers) {
            $val = $r.$h; if ($null -ne $val) {
                $s = [string]$val
                if ($s -match '[,"
]') { '"' + ($s -replace '"','""') + '"' } else { $s }
            } else { '' }
        }
        [void]$sb.AppendLine(($cells -join ','))
    }
    return [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
}