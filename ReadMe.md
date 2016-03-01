#SIL Deployment Helper Module
This module contains four scripts to help with deploying Windows Server Software Inventory Logging (SIL) at scale.
 1. Enable-SILCollector
 2. Enable-SILCollectorVHD
 3. Enable-SILCollectorWithWindowsSetup
 4. Set-SILAPollingAccount


#####Note:
The term ‘Collector’ refers to the Windows Server feature Software Inventory Logging (SIL) component of the overall SIL framework.

The first step is to copy this module down locally and then import it into a PowerShell console opened as an administrator using the Import-Module Cmdlet.  This can be done from any Windows client or server running a current version of PowerShell, and which is on your infrastructure's network.

##1. Enable-SILCollector

This function will enable SIL, on a remote server, to publish inventory data to a SIL Aggregator.  This script can be executed in a loop to configure SIL on multiple computers (Windows Servers only).

### Prerequisites


1. PowerShell remoting must be enabled on both the SIL Aggregator server and the SIL Collector server.
1. Current user must have Administrator rights on both the SIL Aggregator server and SIL Collector server.
1. Current user must be able to execute SIL Aggregator PowerShell cmdlets remotely from current server. This script will run the following two SIL Aggregator cmdlets remotely – 
  1. Get-SILAggregator – to get the ‘TargetUri’ value
  1. Set-SILAggregator -  to set the certificate thumbprint 
1. The SIL Collector server must have the required updates installed
  1. For Windows Server 2012 R2
    * KB3000850, Nov 2014 
    * KB3060681, June 2015
  1. For Windows Server 2012 
    * KB3119938 
  1. For Windows Server 2008 R2 SP1
    * KB3109118
1. The client certificate type is .PFX and not of any other format.

###Parameters:
------------------

| Parameter Name      | Type        | Required  | Description |
|:---|:---|:---|:---|
| SilCollectorServer     | String  |Y	 |Specifies a remote server to be enabled and configured for Software Inventory Logging.|	 
|SilCollectorServerCredential|PSCredential|N|Specifies the credentials that allow this script to connect to the remote SIL Collector server.|
|SilAggregatorServer|String|Y|Specifies the SIL Aggregator server. This server must have Software Inventory Logging Aggregator installed|
|SilAggregatorServerCredential|PSCredential|N|Specifies the credentials that allow this script to connect to the remote SIL Aggregator server.|
|CertificateFilePath|String|Y|Specifies the directory path for the PFX file.|
|CertificatePassword|SecureString|Y|Specifies the password for the imported PFX file in the form of a secure string. **Passwords must be passed in Secure String format**|


Notes: 
 * To obtain a PSCredential object, use the ‘Get-Credential’ Cmdlet. For more information, type Get-Help Get-Credential.
 * For passwords use ConvertTo-SecureString Cmdlet.  Example: $pwd = ConvertTo-SecureString -String 'yourpassword' -AsPlainText -Force 


###Error Messages:
----------------------
| Possible Errors      | Reason |
|:---|:---|
|Error!!! login using admin credentials.|Script is executing from non-admin PS prompt.|
|Error!!! [$CertificateFilePath] is invalid.|Certificate Path on Local System is not valid or accessible.|
|Cannot validate argument on parameter CertificateFilePath. The certificate must be of '.PFX' format.|The client certificate type is not .PFX format.|
|Certificate Password is Incorrect.|Certificate password is incorrect.|
|Required Windows Update(s) are not installed on [$SilCollectorServer].|The SIL Collector server does not have required SIL updates installed.|
|Error!!! Software Inventory Logging Aggregator 1.0 is not installed on [$AggregatorServer].| The SILA Server does not have Software Inventory Logging Aggregator installed.|
|Error in connecting to Aggregator server[$AggregatorServer].|The SIL Aggregator Server is not accessible.|
|Error in connecting to remote server [$SilCollectorServer].|The SIL Collector server is not accessible.|



###Task performed by Enable-SILCollector:
-------------------------

1. Update TrustedHosts settings, if needed, of current Local Computer by adding the SIL Collector server and SIL Aggregator 
Server to trusted hosts list.
2. Copy the pfx client certificate to SIL Collector server.
3. Install Certificate at  \localmachine\MY (Local Computer -> Personal) at SIL Collector server.
4. Get the ‘TargetURI’ value by running the PowerShell cmdlet ‘Get-SILAggregator’ on SIL Aggregator server .
5. Get the certificate thumbprint value from the provided .PFX certificate file.
6. Configure SIL on SIL Collector server by – 
   1) Run ‘Set-SILLogging’ with parameters – ‘TargetUri’ and ‘CertificateThumbprint’
   2) Run ‘Start-SILLogging’ 
7. Run ‘Set-SILAggregator’ on SIL Aggregator server to register certificate thumbprint from step 5 above.
8. Delete the PFX certificate which was copied earlier from SIL Collector server.
9. Validate the SIL configuration by running Publish-SILData cmdlet on remote computer.
10. Revert the TrustedHosts settings updated in step 1.

####Out of Scope:
-------------
1. Polling account setup. The script will not setup any polling account for parent HOST server. The user must 
run Add-SILVMHost command to add the host for Polling.  See Set-SILAPollingAccount in this module.
2. Logging – The output will be displayed to console only. No logging will be done in either text file or event viewer. 

  



##2. Enable-SILCollectorVHD

This function will setup and enable Software Inventory Logging in a Virtual Hard Disk with Windows Server already installed.	

This function can be used to setup Software Inventory Logging in a Virtual Hard Disk so that all VMs created using this configured VHD will have SIL already configured.

The practical uses for this are intended to cover both ‘gold image’ setup for wide deployment across data centers, as well as configuring end user images for cloud deployment.

###Design:
-------
Configuring SIL in a VHD involves two parts –
Part 1 – Ensure a given enterprise cert is installed on every VM created using the VHD to make SIL work on the VM.
Part 2 – Modify the SIL Registry keys in the VHD to enable and configure SIL.

###Prerequisites:
--------------

1. PowerShell remoting must be enabled on both the SIL Aggregator server and the SIL Collector server.
1. Current user must have Administrator rights on both the SIL Aggregator server and SIL Collector server.
1. Current user must be able to execute SIL Aggregator PowerShell cmdlets remotely from current server. This script will run the following two SIL Aggregator cmdlets remotely – 
  1. Get-SILAggregator – to get the ‘TargetUri’ value
  1. Set-SILAggregator -  to set the certificate thumbprint 
1. The SIL Collector server must have the required updates installed
  1. For Windows Server 2012 R2
    * KB3000850, Nov 2014 
    * KB3060681, June 2015
  1. For Windows Server 2012 
    * KB3119938 
  1. For Windows Server 2008 R2 SP1
    * KB3109118
1. The client certificate type is .PFX and not of any other format.


###Parameters:
------------------

| Parameter Name      | Type        | Required  | Description |
|:---|:---|:---|:---|
|VirtualHardDiskPath|String|Y|Specifies the path for a Virtual Hard Disk to be configured. BothVHD and VHDX formats are valid. The Windows Server operating system contained within this VHD must Have SIL feature installed (see prerequisites)|	 
|SilAggregatorServer|String|Y|Specifies the SIL Aggregator server. This server must have Software Inventory Logging Aggregator installed|
|SilAggregatorServerCredential|PSCredential|N|Specifies the credentials that allow this script to connect to the remote SIL Aggregator server.|
|CertificateFilePath|String|Y|Specifies the directory path for the PFX file.|
|CertificatePassword|SecureString|Y|Specifies the password for the imported PFX file in the form of a secure string. **Passwords must be passed in Secure String format**|


Notes: 
 * To obtain a PSCredential object, use the ‘Get-Credential’ Cmdlet. For more information, type Get-Help Get-Credential.
 * For passwords use ConvertTo-SecureString Cmdlet.  Example: $pwd = ConvertTo-SecureString -String 'yourpassword' -AsPlainText -Force 


###Error Messages:
----------------------
| Possible Errors      | Reason |
|:---|:---|
|Error!!! login using admin credentials.|Script is executing from non-admin PS prompt.|
|Error!!! [$CertificateFilePath] is invalid.|Certificate Path on Local System is not valid or accessible.|
|Cannot validate argument on parameter CertificateFilePath. The certificate must be of '.PFX' format.|The client certificate type is not .PFX format.|
|Certificate Password is Incorrect.|Certificate password is incorrect.|
|Required Windows Update(s) are not installed on VirtualHardDisk.|The VHD does not have required SIL updates installed.|
|Cannot validate argument on parameter VirtualHardDiskPath. The VHD File Path must be of '.vhd or .vhdx' format.|The VHD File Path type is not .vhd/.vhdx format.|
|Error!!! Only Reporting Module is found on [$SilAggregatorServer]. Install Software Inventory Logging Aggregator|The SIL Aggregator Server only has Software Inventory Logging Reporting Module installed.|
|Error!!! Software Inventory Logging Aggregator 1.0 is not installed on [$AggregatorServer].| The SILA Server does not have Software Inventory Logging Aggregator installed.|
|Error in connecting to Aggregator server[$AggregatorServer].|The SIL Aggregator Server is not accessible.|
|VHDFile is being used by another process.|VHD File is in use.|
|Software Inventory Logging feature is not found. The VHD may have the Operating System which does not support SIL.|VHD File doesn’t have Software Inventory Logging feature.|




###Task performed by Enable-SILCollectorVHD:
-------------------------

####Part 1 
To make sure that the given enterprise cert is installed in all VMs created using the SIL configured VHD, this script modifies the ‘RunOnce’ registry key of the VHD, and sets another dynamically generated script to execute when a Administrator user logs in to the VM first time.
 1. Checks the certificate Password and get the certificate thumbprint value from the provided .PFX certificate file.
 2. Updates Trusted Hosts settings of Local Computer by adding the Aggregator Server to trusted hosts list, if required.
 3. Checks if Software Inventory Logging Aggregator is installed on Aggregator Server and get the ‘TargetURI’ value by running the PowerShell cmdlet ‘Get-SILAggregator’ remotely on Aggregator server. 
 4. Mounts the VHD
   Mount-VHD -Path $VirtualHardDiskPath
 5. Loads Registry from VHD 
   $RemoteReg=$DriveLetter + ":\Windows\System32\config\Software"
   REG LOAD 'HKLM\REMOTEPC' $RemoteReg
 6. Copy cert file to VHD at “\Scripts”
   Copy-Item -Path $CertificateFilePath -Destination $remoteCert
 7. The script will prepare another .cmd file at run time to import certificate in \localmachine\MY (Local Computer ->       Personal) store on the current running system. This script will run automatically on the VM to install certificate using     required parameters. 

   Set-Variable -Name psPath -Value "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -Option Constant
   Set-Variable -Name certStore -Value "cert:\localmachine\MY" -Option Constant

   ## Encrypt SecureString Password for Certificate to be installed
   $encCertPswd = ConvertFrom-SecureString -SecureString $CertificatePassword -Key (1..16) 

   ## Create a command to import certificate and write it on “EnableSIL.cmd” file
   $cmd = [string]::Format("{0} -CertStoreLocation {1} -FilePath {2} -Password (convertto-securestring -key (1..16) -string     {3})", "Import-PfxCertificate", $certStore, $certFile, $encCertPswd) 
       
   $cmd1 = [string]::Format("{0} -command {1}", $pspath, $cmd)
   Add-Content $SetupFilePath $cmd1 

   ## Add another command to remove the certificate file.
   $cmd = [string]::Format("{0} {1} -ErrorAction Stop", "Remove-Item", $certFile) 
   $cmd2 = [string]::Format("{0} -command {1}", $pspath, $cmd) 
   Add-Content $SetupFilePath "`n$cmd2"

   ## Add another command to remove EnableSIL.cmd file.
   $cmd = [string]::Format("{0} {1} -ErrorAction Stop", "Remove-Item", $filePath)  
   $cmd3 = [string]::Format("{0} -command {1}", $pspath, $cmd) 
   Add-Content $SetupFilePath "`n$cmd3" 

8. Set above dynamically generated EnableSIL.cmd file to a ‘RunOnce’ Registry key in VHD to execute this above script for       every VM on first time start.

   HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
   Set-ItemProperty "HKLM:\REMOTEPC\Microsoft\Windows\CurrentVersion\RunOnce\" -Name "PoshStart" -Value "C:\Scripts   \EnableSIL.cmd"

• Part 2
Load and edit Software Inventory Logging registry entries – 
\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\SoftwareInventoryLogging. 

----------------------------------------------------------------------------------------------------------------------------
|Function				|Value Name		|Data		|Corresponding Cmdlet 			   | |					|			|		|(available only in the runningOS)	   |
----------------------------------------------------------------------------------------------------------------------------
|Start/Stop Feature			|CollectionState	|1 or 0		|Start-SilLogging, Stop-SilLogging	   |
|					|			|		|					   |
|Specifies target aggregation		|TargetUri		|String		|Set-SilLogging -TargetURI		   |
|point on the network			|			|		|					   |
|					|			|		|					   |
|Specifies Certificate Thumbprint or	|CertificateThumbprint	|String		|Set-SilLogging -CertificateThumbprint     |
|Hash of the certificate used for SSL	|			|		|					   |
|authentication for the target webserver|			|		|					   |
|					|			|		|					   |	|Specifies the date and time that the	|CollectionTime		|Default:	|Set-SilLogging -TimeOfDay		   | 
|feature should start (if value set is	|			|2000-01-01T03	|					   |
|in the future according to local system|			|:00:00		|				           |
|time)					|			|		|				           |
----------------------------------------------------------------------------------------------------------------------------			
9. Set the following Registry key values in VHD as following – 
   CollectionState		:1
   TargetUri			:Value received from Step 3
   CertificateThumbprint	:Value reeived from Step 1

10. Run ‘Set-SILAggregator’ on the Aggregator server to register certificate thumbprint from step 1 above.
11. Revert back the TrustedHosts settings updated in step 2.




======================================
3. Enable-SILCollectorWithWindowsSetup
======================================

The function to setup Software Inventory Logging in a Virtual Hard Disk.

This function can be used to setup Software Inventory Logging in a Virtual Hard Disk so that all VMs created using this configured VHD has SIL configured.

The practical uses for this are intended to cover both ‘gold image’ setup for wide deployment across data centers, as well as configuring end user images going from a premises to a cloud deployment.

Design:
-------

Configuring SIL in a VHD involves two parts –
Part 1 – Ensure a given enterprise cert is installed on every VM created using the VHD to make SIL work on the VM.
Part 2 – Start and configure Software Inventory Logging on every VM so that it sends inventory data to the Aggregation server at regular intervals.

This scripts creates or modifies ‘%WINDIR%\Setup\Scripts\SetupComplete.cmd’ file in the VHD to enable and configure SIL. When a new VM is created using the VHD, the Software Inventory Logging is configured after Windows is installed, but before the logon screen appears.

Prerequisites:
--------------

1. The client certificate type is .PFX and not of any other format.
2. The remote computers have required SIL updates instaled – 
   a) For Windows Server 2012 R2
      KB3000850 Nov 2014 
      KB3060681 June 2015
   b) For Windows Server 2012 
      KB3119938 
   c) For Windows Server 2008 R2 SP1
      KB3109118

Parameters:
-----------

----------------------------------------------------------------------------------------------------------------------------
|Sr. No.|Parameter                    |Name Type   |Required|Description						   |
----------------------------------------------------------------------------------------------------------------------------
|1.	|VirtualHardDiskPath          |String	   |Y	    |Specifies the path for a Virtual Hard Disk to be configured.  | |	|			      |		   |	    |BothVHD and VHDX formats are valid.			   |
|	|		    	      |		   |	    |The Windows operating system contained within this VHD must   | |	|			      |		   |	    |have SIL feature installed.				   |
|2.	|CertificateFilePath	      |string	   |Y	    |Specifies the path for the PFX file.			   |
|3.	|CertificatePassword	      |SecureString|Y	    |Specifies the password for the imported PFX file in the form  | |	|			      |		   |	    |of a secure string.					   |
|4.	|SilAggregatorServer	      |String	   |Y	    |Specifies the SIL Aggregator server. This server must have    | |	|			      |		   |	    |Software Inventory Logging Aggregator 1.0  installed.	   |
|5.	|SilAggregatorServerCredential|PSCredential|N	    |Specifies the credentials that allow this script to connect to| |	|			      |		   | 	    |the remote SIL Aggregator server.				   |
|	|			      |		   |	    |To obtain a PSCredential object, use the ‘Get-Credential’     | |	|			      |		   |	    |cmdlet. For more information, type Get-Help Get-Credential.   |
----------------------------------------------------------------------------------------------------------------------------

Validations:
------------

----------------------------------------------------------------------------------------------------------------------------
|Sr. No.|Validations					    |Error Message                                                 |
----------------------------------------------------------------------------------------------------------------------------
|1.	|Script is executing from non admin PS prompt.	    |Error!!! login using admin credentials.			   |
|2.	|The client certificate type is not .PFX format.    |Cannot validate argument on parameter 'CertificateFilePath'.  | |	|						    |The certificate must be of '.PFX' format.			   | 
|3.	|Certificate Path on Local System is not valid 	    |Error!!! [$CertificateFilePath] is invalid.                   |
|	|					            |or accessible.						   |
|4.	|Certificate password is incorrect.		    |Certificate Password is Incorrect.				   |
|5.	|The VHD does not have required SIL updates. 	    |Required Windows Update(s) are not installed on               |
|	|						    |VirtualHardDisk.	                                           |
|6.	|The VHD File Path type is not .vhd/.vhdx format.   |Cannot validate argument on parameter VirtualHardDiskPath.    |
|	|						    |The VHD File Path must be of '.vhd or .vhdx' format.          | 
|7.	|The SIL Aggregator Server only have Software	    |Error!!! Only Reporting Module is found on 		   |	
|	|Inventory Logging Reporting Module installed.	    |[$SilAggregatorServer].Install Software Inventory Logging     | |	|						    |Aggregator.	                                           |
|8.	|The SIL Aggregator Server does not have Software   |Error!!! Software Inventory Logging Aggregator 1.0 is not     |
|	|Inventory Logging Aggregator installed. 	    |installed on [$SilAggregatorServer].			   |
|9.	|The SIL Aggregator Server is not accessible.	    |Error in connecting to Aggregator server			   |
|	|						    |[$SilAggregatorServer].			                   | 
|10.	|VHD File is in use.				    |VHDFile is being used by another process.			   | 
|11.	|VHD File doesn’t have Software Inventory Logging   |Software Inventory Logging feature is not found. The VHD may  |
|	|feature.					    |have the Operating System which does not support SIL. 	   |
---------------------------------------------------------------------------------------------------------------------------- 

Tasks performed
---------------

To make sure that the given enterprise cert is installed in all VMs created using the SIL configured VHD, this script modifies or add the ‘SetupComplete.cmd’ file on the VHD.

1. Validate if required SIL updates are installed or not in the given VHD. If not, then display a warning message.
2. If required, Update TrustedHosts settings of Current Computer where this script is running by adding the Aggregator       Server to trusted hosts list.
3. Copy input Enterprise cert file to VHD at “‘%WINDIR%\Setup\Scripts ”. This cert file will be installed at the time of    VM creation.
4. Get the SIL Aggregation Server URI, ‘TargetURI’ value by running the PowerShell cmdlet ‘Get-SILAggregator’ remotely on    the Aggregator server.
5. Get the certificate thumbprint value from the provided .PFX certificate file. 
6. Encrypt the certificate password.
   $encCertPswd = ConvertFrom-SecureString -SecureString $CertificatePassword -Key (1..16)
7. Add a PowerShell command in SetupComplete.cmd file to import certificate in \localmachine\MY (Local Computer ->       Personal) store on the new VM.
8. Run ‘Set-SILAggregator’ on Aggregator server to register certificate thumbprint from step 5 above.
9. Start and Configure SIL by adding two more commands in SetupComplete.cmd – 
   a) Set-SilLLogging
   b) Start-SilLogging
10. If changed, revert the TrustedHosts settings updated in step 2.




======================================
4. Set-SILAPollingAccount
======================================
The function that sets just enough permissions for a domain user on the host to be used as SILA Polling Account. This function adds the provided domain user account into the Remote Management Users group, Hyper-V administrators group and gives read only access to the root\CIMV2 namespace for Polling to work.

.EXAMPLE

    $targetMachineCredential = Get-Credential
       
    Set-SILAPollingAccount -computername Contoso1 -domain Contosodomain -user existingDomainUser -targetMachineCredential $targetMachineCredential  

References:
-----------

Software Inventory Logging Aggregator
https://technet.microsoft.com/en-us/library/mt572043.aspx

Manage Software Inventory Logging in Windows Server 2012 R2
https://technet.microsoft.com/en-us/library/dn383584.aspx

Software Inventory Logging Aggregator 1.0 for Windows Server
https://www.microsoft.com/en-us/download/details.aspx?id=49046

Add a Custom Script to Windows Setup
https://technet.microsoft.com/en-us/library/cc766314(v=ws.10).aspx

Run and RunOnce Registry Keys
https://msdn.microsoft.com/en-us/library/windows/desktop/aa376977(v=vs.85).aspx


