function Get-DefenderTvmRaw {
    <#
    .SYNOPSIS
        Fetch flat Microsoft Defender TVM vulnerabilities (per-device CVEs) for a specific tenant.
    .PARAMETER TenantId
        Entra tenant ID (same value Standards receive as $TenantFilter).
    .PARAMETER MaxPages
        Optional safety cap on pagination. 0 = unlimited.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [int] $MaxPages = 0
    )

    $scope   = 'https://api.securitycenter.microsoft.com/.default'
    $uri     = 'https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?`$top=999'
    $all     = New-Object System.Collections.Generic.List[object]
    $page    = 0

    Write-LogMessage -API 'DefenderTVM' -tenant $TenantId -message 'Fetching SoftwareVulnerabilitiesByMachine…' -sev 'Debug'

    try {
        do {
            $resp = New-GraphGetRequest -tenantid $TenantId -uri $uri -scope $scope

            # Some helpers return @{value=...; '@odata.nextLink' = ...}, others just the array
            $rows = $null
            $next = $null
            if ($resp -is [System.Collections.IDictionary] -and $resp.ContainsKey('value')) {
                $rows = $resp.value
                $next = $resp.'@odata.nextLink'
            } else {
                $rows = $resp
            }

            if ($rows) { $all.AddRange($rows) }

            $page += 1
            $uri = $next

            if ($MaxPages -gt 0 -and $page -ge $MaxPages) {
                Write-LogMessage -API 'DefenderTVM' -tenant $TenantId -message "Stopped at MaxPages=$MaxPages." -sev 'Warn'
                break
            }
        } while ($uri)

        return $all
    }
    catch {
        $msg = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'DefenderTVM' -tenant $TenantId -message "Error fetching TVM: $msg" -sev 'Error'
        throw
    }
}
