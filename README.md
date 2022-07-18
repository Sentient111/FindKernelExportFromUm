# FindKernelExportFromUm
 
If you are using vulnerable drivers this might be useful.   

## DESCRIPTION
Basically does as the name says. You get kernel exports in this example "NtQueryInformationFile" from usermode without reading from kernel memory.


## HOW IT WORKS
You can get the base addresses from kernel modules from usermode by calling NtQuerySystemInformation with the SystemModuleInformation class.
Then you get the export address from the image on disk and translate the address.

