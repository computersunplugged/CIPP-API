function Push-NinjaOneQueue {
    # Input bindings are passed in via param block.
    param($Item)

    # Write out the queue message and metadata to the information log.
    Write-Host "PowerShell NinjaOne queue trigger function processed work item: $($Item.NinjaAction)"

    Switch ($Item.NinjaAction) {
        'StartAutoMapping' { Invoke-NinjaOneOrgMapping }
        'AutoMapTenant'    { Invoke-NinjaOneOrgMappingTenant -QueueItem $Item }
        'SyncTenant'       { Invoke-NinjaOneTenantSync -QueueItem $Item }
        'SyncTenants'      { Invoke-NinjaOneSync }
<<<<<<< HEAD
=======
        'CveSyncTenant'    { Invoke-NinjaOneCveSyncTenant -QueueItem $Item }
>>>>>>> 10692946b625681c5668488605d72840918772a2
    }
    return $true
}
