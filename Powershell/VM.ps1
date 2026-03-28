function Get-MyAzVMs {
    $vms = Get-AzVM
	$vmsProcessed = @()
	foreach ($vm in $vms) {
		$vmDetailed = Get-AzVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName
		$extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name
		$vmsProcessed += [PSCustomObject]@{
			Name = $vm.Name
			ResourceGroupName = $vm.ResourceGroupName
			Extensions = $extensions
			NetworkInterfaces = $vmDetailed.NetworkProfile.NetworkInterfaces
		}
	}
    return $vmsProcessed
}