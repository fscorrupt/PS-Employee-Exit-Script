<#
.SYNOPSIS
  <Overview of script>

.DESCRIPTION
  <Brief description of script>

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  <Inputs if any, otherwise state None>

.OUTPUTS Log File
  The script log file stored in $env:LOCALAPPDATA\<name>.log

.NOTES
  Version:        1.0
  Author:         Andreas Fenz
  Creation Date:  <Date>
  Purpose/Change: Initial script development

.EXAMPLE
  <Example explanation goes here>
  
  <Example goes here. Repeat this attribute for more than one example>
#>



#######################################################Start Gui##################################################################

#==============================================================================================
# XAML Code
#==============================================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Employee Exit" Height="262" Width="400" WindowStartupLocation="CenterScreen" WindowStyle='None' ResizeMode='NoResize'>
    <Grid Margin="0,0,-0.2,0.2">
        <TextBox HorizontalAlignment="Center" Height="23" TextWrapping="Wrap" Text="Employee Exit" VerticalAlignment="Top" Width="400" Margin="0,-1,-0.2,0" TextAlignment="Center" Foreground="White" Background="#FF98D6EB"/>
        <Label Content="Employee Name" HorizontalAlignment="Left" Margin="0,27,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="#FF98D6EB" Foreground="White"/>
        <Label Content="Representative" HorizontalAlignment="Left" Margin="0,62,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="#FF98D6EB" Foreground="White"/>
        <Label Content="Ticket Number" HorizontalAlignment="Left" Margin="0,97,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="#FF98D6EB" Foreground="White"/>
        <Button Name="okButton" Content="OK" HorizontalAlignment="Left" Margin="0,238,0,0" VerticalAlignment="Top" Width="200" BorderThickness="0" IsDefault="true"/>
        <Button Name="cancelButton" Content="Cancel" HorizontalAlignment="Right" Margin="0,238,0,0" VerticalAlignment="Top" Width="200" BorderThickness="0" IsCancel="True"/>
        <TextBox Name="User" HorizontalAlignment="Left" Height="30" Margin="175,27,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <TextBox Name="deputy" HorizontalAlignment="Left" Height="30" Margin="175,62,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <TextBox Name="TicketNumber" HorizontalAlignment="Left" Height="30" Margin="175,97,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <CheckBox Name="ExpMailbox" Content = 'Export Mailbox' HorizontalAlignment="Left" Margin="0,142,0,0" VerticalAlignment="Top" Height="30" Width="170"/>
        <CheckBox Name="DisMailbox" Content = 'Disable Mailbox' HorizontalAlignment="Left" Margin="0,162,0,0" VerticalAlignment="Top" Height="30" Width="170"/>
        <CheckBox Name="ArUserData" Content = 'Archive User Data and Set Full Permission' HorizontalAlignment="Left" Margin="0,182,0,0" VerticalAlignment="Top" Height="30" Width="250"/>
        <CheckBox Name="DelUserData" Content = 'Delete User Data' HorizontalAlignment="Left" Margin="0,202,0,0" VerticalAlignment="Top" Height="30" Width="170"/>
    </Grid>   
</Window>
'@
#Read XAML
$reader=(New-Object System.Xml.XmlNodeReader $xaml)
try{$Form=[Windows.Markup.XamlReader]::Load( $reader )}
catch{Write-Host "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."; exit}

#===========================================================================
# Store Form Objects In PowerShell
#===========================================================================
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)}

#===========================================================================
# Add events to Form Objects
#===========================================================================

$cancelButton.Add_Click({$Form.DialogResult = $false})
$okButton.Add_Click({$Form.DialogResult = $true})
#===========================================================================
# Shows the form
#===========================================================================
$Result=$Form.ShowDialog() #| Out-Null

#######################################################Functions##################################################################
function Write-log {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path,

		[Parameter(Mandatory = $true)]
		[string]$Message,

		[Parameter(Mandatory = $true)]
		[string]$Component,

		[Parameter(Mandatory = $true)]
		[ValidateSet("Info","Warning","Error")]
		[string]$Type
	)

	switch ($Type) {
		"Info" { [int]$Type = 1 }
		"Warning" { [int]$Type = 2 }
		"Error" { [int]$Type = 3 }
	}

	# Create a log entry
	$Content = "<![LOG[$Message]LOG]!>" + `
 		"<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
 		"date=`"$(Get-Date -Format "M-d-yyyy")`" " + `
 		"component=`"$Component`" " + `
 		"context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
 		"type=`"$Type`" " + `
 		"thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
 		"file=`"`">"

	# Write the line to the log file
	Add-Content -Path $Path -Value $Content
}

function AD-Part {
	if ((Get-ADUser -Identity $User).enabled -eq $true) {
		Disable-ADAccount -Identity $User
		Write-Log -Path $log -Message "AD-Account Disabled..." -Component ActiveDirectory-Function -Type Info
	}

	else {
		Write-Log -Path $log -Message "AD-Account was already deactivated..." -Component ActiveDirectory-Function -Type Warning
	}

	#Remove from Groups
	$Groups = Get-ADPrincipalGroupMembership $User

	foreach ($group in $Groups)
	{
		if ($group.Name -ne "domain users") {
			Get-ADGroup $group | Remove-ADGroupMember -Members $User -ErrorAction SilentlyContinue -ErrorVariable GroupRemove -Confirm:$false
			if ($GroupRemove) {
				Write-Log -Path $log -Message "Couldn't remove from Group - (Access denied): $group" -Component ActiveDirectory-Function -Type Error
			}
			else {
				Write-Log -Path $log -Message "User Removed from group: $group" -Component ActiveDirectory-Function -Type Info }
		}
	}

	#Get User Properties
	$Properties = Get-ADUser -Identity $User -Properties telephoneNumber,mobile,facsimileTelephoneNumber,manager
    if ($Properties.manager){
        $Manager = ($Properties.manager).Split(',')[0].Split('=')[1]
    }

	#Clear User Attributs
	Set-ADUser $User -Clear telephoneNumber,mobile,facsimileTelephoneNumber -ErrorVariable PhoneErrors
	Set-ADUser $User -Clear manager -ErrorVariable ManagerErrors

	#Move User to Retired OU
	$MoveUser = Move-ADObject -Identity "$UserDN" -TargetPath $RetiredOUDN -ErrorVariable MoveErrors -ErrorAction SilentlyContinue

	if ($PhoneErrors) { Write-Log -Path $log -Message $PhoneErrors -Component ActiveDirectory-Function -Type Error }
	else {
		Write-Log -Path $log -Message "Tel: $($Properties.telephoneNumber) cleared..." -Component ActiveDirectory-Function -Type Info
		Write-Log -Path $log -Message "Fax: $($Properties.facsimileTelephoneNumber) cleared..." -Component ActiveDirectory-Function -Type Info
		Write-Log -Path $log -Message "Mobile: $($Properties.mobile) cleared..." -Component ActiveDirectory-Function -Type Info
	}

	if ($ManagerErrors) { Write-Log -Path $log -Message $ManagerErrors -Component ActiveDirectory-Function -Type Error }
	else {
		Write-Log -Path $log -Message "Manager: $Manager - cleared..." -Component ActiveDirectory-Function -Type Info
	}

	if ($MoveErrors) { Write-Log -Path $log -Message "Cannot Move User to Retired OU, Access is Denied...." -Component ActiveDirectory-Function -Type Error }
	else {
		Write-Log -Path $log -Message "Moved to Retired OU: $RetiredOUDN..." -Component ActiveDirectory-Function -Type Info
	}
    Write-Log -Path $log -Message "---------------------------------------" -Component ActiveDirectory-Function -Type Info
}

function Exchange-Part {
	#Export Mailbox
	Write-Log -Path $log -Message "Connect to Exchange..." -Component Exchange-Function -Type Info
	$Output = Import-PSSession $Session -AllowClobber -DisableNameChecking
	$GetMailbox = get-mailbox -Identity $User | Select-Object -ExpandProperty Name
	if (!$GetMailbox) {
		Write-Log -Path $log -Message "No Mailbox found..." -Component Exchange-Function -Type Warning
	}
	else {
		if ($ArMailbox -eq $true) {
			$GetExportRequest = Get-MailboxExportRequest -BatchName $BatchName
			if ($GetExportRequest.Status -eq 'InProgress' -or $GetExportRequest.Status -eq 'Completed') { Write-Log -Path $log -Message "Mailbox Export is already in progress/completed" -Component Exchange-Function -Type Warning }
			else {
				$MailboxExport = New-MailboxExportRequest -Mailbox $User -FilePath $Path -BatchName $BatchName
				$ExportedMailbox = $MailboxExport.Mailbox
				$ExportedMailboxStatus = $MailboxExport.Status
				$ExportedMailboxPath = $MailboxExport.FilePath
				$ExportedMailboxBatchName = $MailboxExport.BatchName
		        Write-Log -Path $log -Message "Exported Mailbox Name: $ExportedMailbox" -Component Exchange-Function -Type Info
		        Write-Log -Path $log -Message "Export Status: $ExportedMailboxStatus" -Component Exchange-Function -Type Info
		        Write-Log -Path $log -Message "Export FilePath: $ExportedMailboxPath" -Component Exchange-Function -Type Info
		        Write-Log -Path $log -Message "Export BatchName: $ExportedMailboxBatchName" -Component Exchange-Function -Type Info
			}
		}

		$HideFromGal = set-mailbox -Identity $User -HiddenFromAddressListsEnabled $true
        Write-Log -Path $log -Message "User hidden from Address List..." -Component Exchange-Function -Type Info

		if ($deputy) {
			$FullPermission = Add-MailboxPermission -Identity $User -User $deputy -AccessRights FullAccess -InheritanceType All
			$FullPermissionSet = $FullPermission.AccessRights
			Write-Log -Path $log -Message "$deputy has now $FullPermissionSet" -Component Exchange-Function -Type Info
		}

		if ($DisMailbox -eq $true) {
			Disable-Mailbox -Identity $User
			Write-Log -Path $log -Message "User Mailbox delted, retained in the mailbox database for 30 days." -Component Exchange-Function -Type Info
		}


		

	}
    Write-Log -Path $log -Message "---------------------------------------" -Component Exchange-Function -Type Info
}

function Skype-Part {
	#Skype
	Write-Log -Path $log -Message "Connect to Skype..." -Component Skype-Function -Type Info
	Remove-PSSession $Session | Out-Null -ErrorVariable PSSession1 -ErrorAction SilentlyContinue
	if ($PSSession1) { Write-Log -Path $log -Message $PSSession1 -Component Skype-Function -Type Error }

	$Output = Import-PSSession $Session2 -AllowClobber -DisableNameChecking
	$GetSkypeUser = Get-CsUser $SkypeID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SipAddress
	if (!$GetSkypeUser)
	{
		Write-Log -Path $log -Message "No Skype User found..." -Component Skype-Function -Type Warning
	}
	else {
		$RewokeCert = Revoke-CsClientCertificate -Identity $aduser.Name
		$DisableSkypeUser = Disable-CsUser -Identity $SkypeID -Passthru
		Write-Log -Path $log -Message "Skype User disabled..." -Component Skype-Function -Type Info
        Write-Log -Path $log -Message "User Certs Rewoked..." -Component Skype-Function -Type Info
	}
	Remove-PSSession $Session2 | Out-Null -ErrorVariable PSSession2 -ErrorAction SilentlyContinue
	if ($PSSession2) { Write-Log -Path $log -Message $PSSession -Component Skype-Function -Type Error }
Write-Log -Path $log -Message "---------------------------------------" -Component Skype-Function -Type Info
}

function Zip-Files {
    if ($PSVersionTable.PSVersion.Major -eq '5'){
    ##############################
	#ZIP User Files
	$name = "$($User)_$Date.zip"

	$Source = $FDR
	$destination = $UserPath + $name
	$FolderSize = "{0:N2} MB" -f ((Get-ChildItem $source -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
	if (Test-Path $destination) { Write-Log -Path $log -Message "Zip file already present, removing Zip File..." -Component Zip-Function -Type Warning; Remove-Item $destination }

	Write-Log -Path $log -Message "Zipping Files Started..." -Component Zip-Function -Type Info
	Write-Log -Path $log -Message "Folder Size: $FolderSize" -Component Zip-Function -Type Info
	Compress-Archive -Path $Source -DestinationPath $destination -Force -Confirm:$false
	Write-Log -Path $log -Message "User Files Zipped to: $destination" -Component Zip-Function -Type Info
    }
    Else {
    ##############################
    #ZIP User Files
    $name = "$User" + "_" + "$Date" + ".zip"

    $source = $FDR
    $destination = $UserPath+$name
    $FolderSize= "{0:N2} MB" -f ((Get-ChildItem $source -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
    If(Test-path $destination) { Write-Log -Path $log -Message "Zip file already present, removing Zip File..." -Component Zip-Function -Type Warning;Remove-item $destination}

    Write-Log -Path $log -Message "Zipping Files Started" -Component Zip-Function -Type Info
    Write-Log -Path $log -Message "Folder Size: $FolderSize" -Component Zip-Function -Type Info
    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($Source, $destination)
    Write-Log -Path $log -Message "User Files Zipped to: $destination" -Component Zip-Function -Type Info
    Write-Log -Path $log -Message "---------------------------------------" -Component Zip-Function -Type Info
    }
##############################
	##############################
}

function Set-FullPermission {
	#Set Full Permission
	$acl = Get-Acl $FDR
	$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ("$Domain\$deputy","FullControl",”ContainerInherit,ObjectInherit”,”None”,"Allow")
	$acl.SetAccessRule($AccessRule)
	$acl | Set-Acl $FDR
	$GetACL = Get-Acl $FDR | Select-Object -ExpandProperty Access | Where-Object identityreference -EQ "$Domain\$deputy" | Select-Object -ExpandProperty filesystemrights
	if ($GetACL -eq 'FullControl') {
		Write-Log -Path $log -Message "Full Permission Set for: $deputy" -Component ACL-Function -Type Info
	}

	else {
		Write-Log -Path $log -Message "Full Permission not set for: $deputy" -Component ACL-Function -Type Error 
    }
    Write-Log -Path $log -Message "---------------------------------------" -Component ACL-Function -Type Info
}

function Del-UserData {
	
	if (Test-Path $FDR) { Remove-Item $FDR -Force -Confirm:$false }
	if (!(Test-Path $FDR)) {
		Write-Log -Path $log -Message "User Files deleted: $FDR" -Component DelUserData-Function -Type Info
	}
	else {
		Write-Log -Path $log -Message "User Files not deleted: $FDR" -Component DelUserData-Function -Type Warning
	}
Write-Log -Path $log -Message "---------------------------------------" -Component DelUserData-Function -Type Info
}

function Download-Cmtrace {
(New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/5/0/8/508918E1-3627-4383-B7D8-AA07B3490D21/ConfigMgrTools.msi", "C:\Windows\Temp\ConfigMgrTools.msi")
Write-Log -Path $log -Message "Downloading ConfigMgrTools started..." -Component Download-Cmtrace -Type Info

$MSIFileSize = "5664768"
#This is the known complete size of the MSI file; prevents attempted execution prior to complete download

do{
    Start-Sleep -Seconds 2
    $FileSize= (Get-Item C:\Windows\Temp\ConfigMgrTools.msi).Length
} until ($FileSize -eq $MSIFileSize)

## Be sure to check the MSI flags applicable to your MSI
Write-Log -Path $log -Message "Installing ConfigMgrTools started..." -Component Download-Cmtrace -Type Info
Msiexec /i C:\Windows\Temp\ConfigMgrTools.msi /norestart /passive /qn /+lvx* $log
Write-Log -Path $log -Message "---------------------------------------" -Component Download-Cmtrace -Type Info
}

Function Read-CMLogfile {
    
    $result = $null
    $result = @()
        $cmlogformat = $false
        $cmslimlogformat = $false
        # Use .Net function instead of Get-Content, much faster.
        $file = [System.io.File]::Open($log, 'Open', 'Read', 'ReadWrite')
        $reader = New-Object System.IO.StreamReader($file)
        [string]$LogFileRaw = $reader.ReadToEnd()
        $reader.Close()
        $file.Close()

        $pattern = "LOG\[(.*?)\]LOG(.*?)time(.*?)date"
        $patternslim = '\$\$\<(.*?)\>\<thread='
        
        if(([Regex]::Match($LogFileRaw, $pattern)).Success -eq $true){ $cmlogformat = $true}
        elseif(([Regex]::Match($LogFileRaw, $patternslim)).Success -eq $true){ $cmslimlogformat = $true}
        
        If($cmlogformat){
                
            # Split each Logentry into an array since each entry can span over multiple lines
            $logarray = $LogFileRaw -split "<!"

            foreach($logline in $logarray){
                
                If($logline){            
                    # split Log text and meta data values
                    $metadata = $logline -split "><"

                    # Clean up Log text by stripping the start and end of each entry
                    $logtext = ($metadata[0]).Substring(0,($metadata[0]).Length-6).Substring(5)
            
                    # Split metadata into an array
                    $metaarray = $metadata[1] -split '"'

                    # Rebuild the result into a custom PSObject
                    $result += $logtext |select-object @{Label="LogText";Expression={$logtext}}, @{Label="Type";Expression={[LogType]$metaarray[9]}},@{Label="Component";Expression={$metaarray[5]}}
                }        
            }
        }

        If($cmslimlogformat){
       
        # Split each Logentry into an array since each entry can span over multiple lines
        $logarray = $LogFileRaw -split [System.Environment]::NewLine
              
        foreach($logline in $logarray){
            
            If($logline){  

                    # split Log text and meta data values
                    $metadata = $logline -split '\$\$<'

                    # Clean up Log text by stripping the start and end of each entry
                    $logtext = $metadata[0]
            
                    # Split metadata into an array
                    $metaarray = $metadata[1] -split '><'
                    If($logtext){
                        # Rebuild the result into a custom PSObject
                        If($metaarray[1] -match '\+'){
                            $result += $logtext |select-object @{Label="LogText";Expression={$logtext}}, @{Label="Type";Expression={[LogType]0}},@{Label="Component";Expression={$metaarray[0]}}
                        }
                        else{
                            $result += $logtext |select-object @{Label="LogText";Expression={$logtext}}, @{Label="Type";Expression={[LogType]0}},@{Label="Component";Expression={$metaarray[0]}}
                        }
                    }
                }
            }
        }
    

    
    $result #return data
}

#######################################################Start the Script/Functions#################################################


if ($Result -eq 'OK'){
#######################################################Variables##################################################################

#GUI Values
$User = if ($User.Text) { $User.Text }
$deputy = if ($deputy.Text) { $deputy.Text }
$TicketNumber = if ($TicketNumber.Text) { $TicketNumber.Text }
if ($ExpMailbox.IsChecked -eq $true) { $ArMailbox = $true }
if ($DisMailbox.IsChecked -eq $true) { $DisMailbox = $true }
if ($ArUserData.IsChecked -eq $true) { $ArUserData = $true }
if ($DelUserData.IsChecked -eq $true) { $DelUserData = $true }

#Global Variables
$Version = "v2.1"
$Date = Get-Date -Format yyyyMMdd
$log = "$env:LOCALAPPDATA\EmployeeExit_$User" + "_$Date.log"

#Remove Old Log File
if (Test-Path $log) { Remove-Item $log -Force -Confirm:$false; Write-Log -Path $log -Message "Old Logfile removed..." -Component Script-Information -Type Warning }

Write-Log -Path $log -Message "Employee Exit Script - $Version" -Component Script-Information -Type Info
Write-Log -Path $log -Message "Script started from, $env:USERNAME" -Component Script-Information -Type Info
Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info

##################
#Adjust Variables#
##################

<#

Based on your AD Structure you can adjust the Location.
I´m Using it to Determinate Location and assign new Value, because i can build Server name with it
For Example, if you are based in Spain, and your Distinguished Name looks like this:

"CN=User NAme,OU=Workers,OU=Users,OU=Spain,OU=$Domain,DC=$Domain,DC=LOCAL"

Im Splitting it to get "Spain", based on Spain i would Assign our Company Special Location Name for Building the Server Name.

If you only have one Location you can remove Location and add the Servername in "Folderredirection" Vaariable.

#>


#Find Location
$Location = (Get-ADUser $User).distinguishedName.Split(',')[-4].Split('=')[1]

#Determinate User Location
If ($Location -eq 'Spain'){$Location='SpecialLocationCode'}
If ($Location -eq 'Retired'){write-host "User is in Retired OU, please enter Location: "-ForegroundColor Yellow -NoNewline;$Location= Read-host}

#Folderredirection
$ServerName= "\\ServerName"+$Location
$FDR = "$ServerName\user\$User"
#Archive
$ArchiveServer="\\ServerName"
$UserPath = "$ArchiveServer\bdarchive$\UserData\"
#AD
$Domain=(Get-WmiObject win32_computersystem).Domain.split('.')[0]
$UserDN = (Get-ADUser $User).DistinguishedName
$RetiredOU = $UserDN.split(",")[-4].split("=")[1]
$RetiredOUDN = "OU=$RetiredOU,OU=Retired,DC=$Domain,DC=LOCAL"
#Exchange
$Path = "$ArchiveServer\bdarchive$\PST\$User$Date.pst"
$Exchange = "ExchangeServerName.$Domain.local"
$BatchName = "Export_$User-$TicketNumber"
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$Exchange/powershell
#Skype
$SkypeID = $Domain+"\"+$User
$Skype = "SkypeServerName.$Domain.local"
$aduser = Get-ADUser $User
$Session2 = New-PSSession -ConfigurationName Microsoft.Powershell -ConnectionUri https://$Skype/OcsPowerShell -Authentication Negotiate
#Mail
$from="EmployExitScript@$Domain.eu"
$to="it.servicedesk@$Domain.eu"
$SMTP="internalmail.$Domain.local"
#Tools
$cmtrace="C:\Program Files (x86)\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"

######################
#Adjust Variables END#
######################

#######################################################Run the Script/Functions##################################################

#Open/Install CmTrace
if (Test-Path $cmtrace){
Write-Log -Path $log -Message "CmTrace installed, open Log File..." -Component Script-Information -Type Info
& $cmtrace $log
}
Else {
Write-Log -Path $log -Message "CmTrace not installed..." -Component Script-Information -Type Warning
Download-Cmtrace
& $cmtrace $log
}
Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info
Write-Log -Path $log -Message "Script Input Parameter..." -Component Script-Information -Type Info
Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info

Write-Log -Path $log -Message "User: $User" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Deputy: $deputy" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Standort: $Location" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Ticketnumber: $TicketNumber" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Export Mailbox: $($GuiExpMailbox.CheckState)" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Disable Mailbox: $($GuiDisMailbox.CheckState)" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Archive User Data: $($GuiArUserData.CheckState)" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "Delete User Data: $($GuiDelUserData.CheckState)" -Component Script-InputData -Type Info
Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info
#AD/Skype/Exchange
if ($Result -eq 'OK' -and $User) {
	AD-Part
	Exchange-Part
	Skype-Part
}


#Zip User Files and Set Full Permission

if ($ArUserData -eq $true) {
$TestFDR=Test-Path $FDR

if ($TestFDR -eq $true) {		
		Zip-Files		
		if ($deputy){
        Set-FullPermission}
	}
if ($TestFDR -eq $false) {
    Write-Log -Path $log -Message "No User Files found, can't delete..." -Component ArchiveUserData -Type Warning
    Write-Log -Path $log -Message "---------------------------------------" -Component ArchiveUserData -Type Info
    }  
}
  
if ($ArUserData -ne $true) {
		Write-Log -Path $log -Message "Archive User Data not Checked..." -Component ArchiveUserData -Type Info
        Write-Log -Path $log -Message "---------------------------------------" -Component ArchiveUserData -Type Info
	}

#Delte User Files
if ($DelUserData -eq $true){
$TestFDR=Test-Path $FDR

if ($TestFDR -eq $true) {	
    Del-UserData
	}

if ($TestFDR -eq $false) {
    Write-Log -Path $log -Message "No User Files found, can't delete..." -Component DelteUserData -Type Warning
    Write-Log -Path $log -Message "---------------------------------------" -Component DelteUserData -Type Info
    }  
}
if ($DelUserData -ne $true){
		Write-Log -Path $log -Message "Delete User Data not Checked..." -Component DelteUserData -Type Info
        Write-Log -Path $log -Message "---------------------------------------" -Component DelteUserData -Type Info
	}

Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info
Write-Log -Path $log -Message "Employee Exit Script finished..." -Component Script-Information -Type Info
Write-Log -Path $log -Message "---------------------------------------" -Component Script-Information -Type Info
Write-Log -Path $log -Message "If Ticketnumber entered, Log content will be sent to Ticketsystem..." -Component Script-Information -Type Info

#Get Log Output for Mail Body

Add-Type -TypeDefinition @"
    public enum LogType
    {
        None,
        Informational,
        Warning,
        Error
     }
"@

$Body = Read-CMLogfile |Where-Object {$_.Type -ge ([LogType]::($LogLevel).value__)} |ft -Wrap |Out-String
$Body = '<pre>{0}</pre>' -f [System.Net.WebUtility]::HtmlEncode($Body)

#Send Mail
if ($TicketNumber) { Send-MailMessage -To $to -From $from -Subject "[#$TicketNumber]" -SmtpServer $SMTP -Body $Body -BodyAsHtml }


Pause

}
Else {Exit}



