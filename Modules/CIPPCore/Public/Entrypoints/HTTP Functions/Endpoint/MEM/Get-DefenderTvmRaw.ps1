function Get-DefenderTvmRaw {
    <#
    .SYNOPSIS
        Fetch Defender TVM SoftwareVulnerabilitiesByMachine with paging.
    .PARAMETER TenantId
        Microsoft Entra tenant id to query.
    .PARAMETER MaxPages
        Optional page cap (0 = no cap).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [int]$MaxPages = 0
    )

    $scope = 'https://api.securitycenter.microsoft.com/.default'
    $uri   = 'https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?$top=999'
    $all   = New-Object System.Collections.Generic.List[object]
    $page  = 0

    Write-LogMessage -API 'DefenderTVM' -tenant $TenantId -message 'Fetching SoftwareVulnerabilitiesByMachine…' -Sev 'Debug'
    try {
        do {
            $resp = New-GraphGetRequest -tenantid $TenantId -uri $uri -scope $scope
            if ($resp -is [System.Collections.IDictionary] -and $resp.ContainsKey('value')) {
                $rows = $resp.value
                $uri  = $resp.'@odata.nextLink'
            } else {
                $rows = $resp
                $uri  = $null
            }
            if ($rows) { $all.AddRange($rows) }
            $page++
        } while ($uri -and ($MaxPages -eq 0 -or $page -lt $MaxPages))

        return $all
    }
    catch {
        Write-LogMessage -API 'DefenderTVM' -tenant $TenantId -message ("Error: {0}" -f $_.Exception.Message) -Sev 'Error'
        throw
    }
}
