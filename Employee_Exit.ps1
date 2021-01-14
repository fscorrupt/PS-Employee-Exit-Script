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
  Version:        2.0
  Author:         Andreas Fenz
  Creation Date:  14.01.2021
  Purpose/Change: Initial script development
.EXAMPLE
  <Example explanation goes here>
  
  <Example goes here. Repeat this attribute for more than one example>
#>

#######################################################Start Gui##################################################################

#################################################################

#Required Modules:
Install-Module -Name ActiveDirectory -Force
Install-Module -Name PoshProgressBar -Force

#Adjust Variables on Line: 975 - 1033

#################################################################
#Importing ADModule for GUI Live Search.
Import-Module -Name ActiveDirectory   

#The Active Directory domain to use
$domain = Get-ADDomain 
 
#Synchronize multithreaded access to objects
$syncHashADULForm = [hashtable]::Synchronized(@{})
$newRunspaceADUL = [runspacefactory]::CreateRunspace()
$newRunspaceADUL.ApartmentState = 'STA'
$newRunspaceADUL.ThreadOptions = 'ReuseThread'         
$newRunspaceADUL.Open()
#Sharing Variables and Live Objects Between PowerShell Runspaces
$newRunspaceADUL.SessionStateProxy.SetVariable('syncHashADULForm',$syncHashADULForm)     
$newRunspaceADUL.SessionStateProxy.SetVariable('domainSVar',$domain)        
$psCmdADUL = [PowerShell]::Create().AddScript({
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
        [ValidateSet('Info','Warning','Error')]
        [string]$Type
      )

      switch ($Type) {
        'Info' 
        {
          [int]$Type = 1
        }
        'Warning' 
        {
          [int]$Type = 2
        }
        'Error' 
        {
          [int]$Type = 3
        }
      }

      # Create a log entry
      $Content = "<![LOG[$Message]LOG]!>" + `
      "<time=`"$(Get-Date -Format 'HH:mm:ss.ffffff')`" " + `
      "date=`"$(Get-Date -Format 'M-d-yyyy')`" " + `
      "component=`"$Component`" " + `
      "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
      "type=`"$Type`" " + `
      "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
      "file=`"`">"

      # Write the line to the log file
      Add-Content -Path $Path -Value $Content -Force -Confirm:$false
    }
    function SleepProgress ([hashtable]$SleepHash) {
      [int]$SleepSeconds = 0
      foreach ($Key in $SleepHash.Keys) 
      {
        switch ($Key) {
          'Seconds' 
          {
            $SleepSeconds = $SleepSeconds + $SleepHash.Get_Item($Key)
          }
          'Minutes' 
          {
            $SleepSeconds = $SleepSeconds + ($SleepHash.Get_Item($Key) * 60)
          }
          'Hours' 
          {
            $SleepSeconds = $SleepSeconds + ($SleepHash.Get_Item($Key) * 60 * 60)
          }
        }
      }
      for ($Count = 0; $Count -lt $SleepSeconds; $Count++) 
      {
        $SleepSecondsString = [convert]::ToString($SleepSeconds)
        Write-Progress -Activity "Please wait for $SleepSecondsString seconds" -Status 'Sleeping' -PercentComplete ($Count / $SleepSeconds * 100)
        Start-Sleep -Seconds 1
      }
      Write-Progress -Activity "Please wait for $SleepSecondsString seconds" -Completed
    }
    function AD-Part {
      $GetADUser = Get-ADUser -Identity $User -Properties *
      $PrimaryComputer = $GetADUser.'msDS-PrimaryComputer'
      $UserMailboxLocation = ($GetADUser).msExchRemoteRecipientType
			
      if ($GetADUser.enabled -eq $true) 
      {
        Disable-ADAccount -Identity $User
        Write-log -Path $log -Message 'AD-Account Disabled...' -Component ActiveDirectory-Function -Type Info
      }

      else 
      {
        Write-log -Path $log -Message 'AD-Account was already deactivated...' -Component ActiveDirectory-Function -Type Warning
      }
			
      #Remove from Groups
      $Groups = Get-ADPrincipalGroupMembership -Identity $User
			
      $DomainUsersGroupToken = (Get-ADGroup "Domain Users" -Properties PrimaryGroupToken).PrimaryGroupToken
      $DomainGuestsGroupToken = (Get-ADGroup "Domain Guests" -Properties PrimaryGroupToken).PrimaryGroupToken
      $UsersPrimaryGroupToken = $GetADUser.PrimaryGroupID
						
      if ($Groups.name -notcontains 'Domain Guests'){
        Add-ADGroupMember -Identity "Domain Guests" -Members $User -ErrorAction SilentlyContinue -ErrorVariable GroupAdd -Confirm:$False
        if ($Groupadd) 
        {
          Write-log -Path $log -Message "Couldn't Add $User to 'Domain Guests' - (Access denied)" -Component ActiveDirectory-Function -Type Error
        }
        else 
        {
          Write-log -Path $log -Message "User Added to 'Domain Guests'" -Component ActiveDirectory-Function -Type Info
          $Groups = Get-ADPrincipalGroupMembership -Identity $User
        }
      }
			
      if ($UsersPrimaryGroupToken -eq $DomainUsersGroupToken){
        Set-ADUser -Identity $User -Replace @{PrimaryGroupID="$DomainGuestsGroupToken"} -ErrorAction SilentlyContinue
        $GetADUser = Get-ADUser -Identity $User -Properties *
        $UsersPrimaryGroupToken = $GetADUser.PrimaryGroupID
        if ($UsersPrimaryGroupToken -eq $DomainGuestsGroupToken){
          Write-log -Path $log -Message "User´s Primary Group changed to 'Domain Guests'" -Component ActiveDirectory-Function -Type Info
        }
        Else {
          Write-log -Path $log -Message "Couldn´t Change User´s Primary Group to 'Domain Guests' - (Access denied)" -Component ActiveDirectory-Function -Type Error 
        }
      }
      Else {
        Write-log -Path $log -Message "User´s Primary Group already is 'Domain Guests'" -Component ActiveDirectory-Function -Type Info
      }
			
      foreach ($group in $Groups)
      {
        if ($group.Name -like 'ReportingGroup {*'){$CRMUser = $true}
        Else {
          if ($group.Name -notlike 'Domain Guests') 
          {
            Get-ADGroup $group | Remove-ADGroupMember -Members $User -ErrorAction SilentlyContinue -ErrorVariable GroupRemove -Confirm:$False
            if ($GroupRemove) 
            {
              Write-log -Path $log -Message "Couldn't remove from Group - (Access denied): $($group.name)" -Component ActiveDirectory-Function -Type Error
            }
            else 
            {
              Write-log -Path $log -Message "User Removed from group: $($group.name)" -Component ActiveDirectory-Function -Type Info
            }
          }
        }
      }
      if ($CRMUser){
        Write-log -Path $log -Message "$User has CRM ReportingGroups, Info Mail will be sent to $tocrm..." -Component ActiveDirectory-Function -Type Warning
      }	
			
		
      #Get User Properties
			
      if ($GetADUser.manager)
      {
        $Manager = ($GetADUser.manager).Split(',')[0].Split('=')[1]
      }
			
			
      #Clear User Attributs
      if ($GetADUser.ipPhone){
        Set-ADUser -Identity $User -Clear ipPhone -ErrorVariable ipPhoneError
        Write-log -Path $log -Message "IpPhone: $($GetADUser.ipPhone) cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "IpPhone Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($GetADUser.telephoneNumber){
        Set-ADUser -Identity $User -Clear telephoneNumber -ErrorVariable telephoneNumberError
        Write-log -Path $log -Message "Tel: $($GetADUser.telephoneNumber) cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "Tel. Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($GetADUser.facsimileTelephoneNumber){
        Set-ADUser -Identity $User -Clear facsimileTelephoneNumber -ErrorVariable facsimileTelephoneNumberError
        Write-log -Path $log -Message "Fax: $($GetADUser.facsimileTelephoneNumber) cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "Fax Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($GetADUser.mobile){
        Set-ADUser -Identity $User -Clear mobile -ErrorVariable mobileError
        Write-log -Path $log -Message "Mobile: $($GetADUser.mobile) cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "Mobile Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($PrimaryComputer){
        Set-ADUser -Identity $User -Clear 'msDS-PrimaryComputer' -ErrorVariable PrimaryComputerError
        Write-log -Path $log -Message "PrimaryComputer: $PrimaryComputer cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "PrimaryComputer Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($Manager){
        Set-ADUser -Identity $User -Clear manager -ErrorVariable ManagerErrors
        Write-log -Path $log -Message "Manager: $Manager cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "Manager Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($GetADUser.thumbnailPhoto){
        Set-ADUser -Identity $User -Clear thumbnailPhoto -ErrorVariable ThumbnailError
        Write-log -Path $log -Message "Thumbnail cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "Thumbnail Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }
      if ($GetADUser.EmployeeID){
        Set-ADUser -Identity $User -Clear employeeID -ErrorVariable employeeIDError
        Write-log -Path $log -Message "EmployeeID: $($GetADUser.EmployeeID) cleared..." -Component ActiveDirectory-Function -Type Info
      }
      Else {
        Write-log -Path $log -Message "EmployeeID Attribute empty..." -Component ActiveDirectory-Function -Type Info
      }

      #Write Clear Errors
      if ($ipPhoneError){
        Write-log -Path $log -Message "Failed to clear IpPhone - $ipPhoneError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($employeeIDError){
        Write-log -Path $log -Message "Failed to clear EmployeeID - $employeeIDError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($telephoneNumberError){
        Write-log -Path $log -Message "Failed to clear TelNumber - $telephoneNumberError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($facsimileTelephoneNumberError){
        Write-log -Path $log -Message "Failed to clear FaxNumber - $facsimileTelephoneNumberError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($mobileError){
        Write-log -Path $log -Message "Failed to clear MobileNumber - $mobileError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($PrimaryComputerError){
        Write-log -Path $log -Message "Failed to clear PrimaryComputer - $PrimaryComputerError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($ManagerErrors){
        Write-log -Path $log -Message "Failed to clear Manager - $ManagerErrors..." -Component ActiveDirectory-Function -Type Error
      }
      if ($ThumbnailError){
        Write-log -Path $log -Message "Failed to clear Thumbnail - $ThumbnailError..." -Component ActiveDirectory-Function -Type Error
      }
      if ($employeeIDError){
        Write-log -Path $log -Message "Failed to clear EmployeeID - $employeeIDError..." -Component ActiveDirectory-Function -Type Error
      }
																					
			
      #Move User to Retired OU
      if($Retired -eq 'Retired')
      {
        Write-log -Path $log -Message 'User is already in Retired OU...' -Component ActiveDirectory-Function -Type warning
      }
      Else
      {
        $MoveUser = Move-ADObject -Identity "$UserDN" -TargetPath $RetiredOUDN -ErrorVariable MoveErrors -ErrorAction SilentlyContinue
        Write-log -Path $log -Message "Moved to Retired OU: $RetiredOUDN..." -Component ActiveDirectory-Function -Type Info
      }

      if ($MoveErrors) 
      {
        Write-log -Path $log -Message 'Cannot Move User to Retired OU, Access is Denied....' -Component ActiveDirectory-Function -Type Error
      }
      Write-log -Path $log -Message '---------------------------------------' -Component ActiveDirectory-Function -Type Info
    }
    function Exchange-Part {
      #Export Mailbox
      Write-log -Path $log -Message 'Connect to Exchange...' -Component Exchange-Function -Type Info
      $Output = Import-PSSession -Session $Session -AllowClobber -DisableNameChecking
      $GetMailbox = get-casmailbox -Identity $User
      if (!$GetMailbox) 
      {
        Write-log -Path $log -Message 'No Mailbox found...' -Component Exchange-Function -Type Warning
      }
      else 
      {
        if ($ArMailbox -eq $true) 
        {
          $GetExportRequest = Get-MailboxExportRequest -BatchName $BatchName
          if ($GetExportRequest.Status -eq 'InProgress' -or $GetExportRequest.Status -eq 'Completed') 
          {
            Write-log -Path $log -Message 'Mailbox Export is already in progress/completed' -Component Exchange-Function -Type Warning
          }
          else 
          {
            $MailboxSize = (Get-MailboxStatistics -Identity $User).totalitemsize.value.tostring().Split('(')[0]
            $MailboxExport = New-MailboxExportRequest -Mailbox $User -FilePath $Path -BatchName $BatchName -BadItemLimit 20 -WarningAction SilentlyContinue
				
            $ExportedMailbox = $MailboxExport.Mailbox
            $ExportedMailboxStatus = $MailboxExport.Status
            $ExportedMailboxPath = $MailboxExport.FilePath
            $ExportedMailboxBatchName = $MailboxExport.BatchName
				
            Write-log -Path $log -Message "Mailbox Size: $MailboxSize" -Component Exchange-Function -Type Info
            Write-log -Path $log -Message "Exported Mailbox Name: $ExportedMailbox" -Component Exchange-Function -Type Info
            Write-log -Path $log -Message "Export Status: $ExportedMailboxStatus" -Component Exchange-Function -Type Info
            Write-log -Path $log -Message "Export FilePath: $ExportedMailboxPath" -Component Exchange-Function -Type Info
            Write-log -Path $log -Message "Export BatchName: $ExportedMailboxBatchName" -Component Exchange-Function -Type Info	
								
            #Get Export Status
            Start-Sleep -Seconds 5
            Write-log -Path $log -Message 'Sleeping for 5 Seconds' -Component Exchange-Function -Type Info
            $ExportStats = Get-MailboxExportRequest -BatchName $BatchName | Get-MailboxExportRequestStatistics 
            $Percent = $ExportStats.PercentComplete
            Write-log -Path $log -Message 'Mailbox Export Started...' -Component Exchange-Function -Type Info
            $ProgressBar = New-ProgressBar -MaterialDesign -Type Horizontal -PrimaryColor LightBlue -AccentColor Blue -Size Medium -Theme Dark
						
            while ($Percent -lt 100) 
            {	
              ## -- Execute The PowerShell Code and Update the Status of the Progress-Bar
              $ExportStats = Get-MailboxExportRequest -BatchName $BatchName | Get-MailboxExportRequestStatistics 
              $Percent = $ExportStats.PercentComplete
              Write-ProgressBar -ProgressBar $ProgressBar -Activity 'Mailbox Export' -PercentComplete $Percent -CurrentOperation 'Exporting Mailbox...'															
              Start-Sleep -Seconds 10
            }
						                    
            Close-ProgressBar -ProgressBar $ProgressBar               
							
            Write-log -Path $log -Message "Exchange Mailbox Export for $($ExportStats.SourceAlias), finished..." -Component Exchange-Function -Type Info  
          }			
        }
      }
	
      $ExportStats = Get-MailboxExportRequest -BatchName $BatchName | Get-MailboxExportRequestStatistics 
      IF ($ExportStats.Status -eq 'Failed') 
      { 
        Get-MailboxExportRequest -BatchName $BatchName | Resume-MailboxExportRequest
        Write-log -Path $log -Message "The Exchange Mailbox Export for $($ExportStats.SourceAlias) failed but was resumed..." -Component Exchange-Function -Type Error
      }

      IF ($ExportStats.Status -eq 'Completed') 
      { 
        Get-MailboxExportRequest -BatchName $BatchName | Remove-MailboxExportRequest -Confirm:$False
        Write-log -Path $log -Message "The Exchange Mailbox Export for $($ExportStats.SourceAlias) is completed..." -Component Exchange-Function -Type Info                   
      }						
	
      if (!$GetMailbox.HiddenFromAddressListsEnabled)
      {	
        $HideFromGal = set-mailbox -Identity $User -HiddenFromAddressListsEnabled $true
        Write-log -Path $log -Message 'User hidden from Address List...' -Component Exchange-Function -Type Info
      }
      if ($GetMailbox.activesyncenabled -eq $true)
      {		
        $DisableActiveSync = Set-CasMailbox -Identity $User -ActiveSyncEnabled $False
        Write-log -Path $log -Message 'ActiveSync disabled...' -Component Exchange-Function -Type Info
      }
		
      #Remove UserPicture
      $Picture = Remove-UserPhoto -Identity $User -Confirm:$False -ClearMailboxPhotoRecord
      Write-log -Path $log -Message 'User Picture - removed...' -Component Exchange-Function -Type Info
		
      #Get Active Sync Devices
      $Devices = Get-MobileDevice -Mailbox $User
			
      If ($Devices)
      {
        foreach ($Device in $Devices)
        {
          $Device | Remove-MobileDevice -confirm:$False 
          Write-log -Path $log -Message "$($Device.Name) - removed..." -Component Exchange-Function -Type Info
        }
      }
      if ($deputy) 
      {
        $FullPermission = Add-MailboxPermission -Identity $User -User $deputy -AccessRights FullAccess -InheritanceType All
        $FullPermissionSet = $FullPermission.AccessRights
        Write-log -Path $log -Message "$deputy has now $FullPermissionSet" -Component Exchange-Function -Type Info
      }
      if ($DisMailbox -eq $true -and ($GetMailbox)) 
      {
        #Write-Log -Path $log -Message "Confirm the delete in Powershell window..." -Component Exchange-Function -Type Warning
        Disable-Mailbox -Identity $User -Confirm:$False
        #if user is remote then -> disable-remotemailbox -identitiy $user
        Write-log -Path $log -Message 'User Mailbox delted, retained in the mailbox database for 30 days.' -Component Exchange-Function -Type Info
      }
      Write-log -Path $log -Message '---------------------------------------' -Component Exchange-Function -Type Info
    }
    function Skype-Part {
      $SkypeSession = New-PSSession -ConfigurationName Microsoft.Powershell -ConnectionUri https://$Skype/OcsPowerShell -Authentication Negotiate
      #Skype
      Write-log -Path $log -Message 'Trying to connect to Skype Server...' -Component Skype-Function -Type Info
				
      if ($SkypeSession.ComputerName -eq $Skype -and $SkypeSession.State -eq 'Opened')
      {
        $Output = Import-PSSession -Session $SkypeSession -AllowClobber -DisableNameChecking
        Write-log -Path $log -Message 'Successfully connected to Skype Server...' -Component Skype-Function -Type Info	
				
        $GetSkypeUser = Get-CsUser $SkypeID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SipAddress
        if (!$GetSkypeUser)
        {
          Write-log -Path $log -Message 'No Skype User found...' -Component Skype-Function -Type Warning
          Write-log -Path $log -Message '---------------------------------------' -Component Skype-Function -Type Info
        }
        if ($GetSkypeUser)
        {
          $RewokeCert = Revoke-CsClientCertificate -Identity $aduser.Name
          $DisableSkypeUser = Disable-CsUser -Identity $SkypeID -Passthru
          Write-log -Path $log -Message 'Skype User disabled...' -Component Skype-Function -Type Info
          Write-log -Path $log -Message 'User Certs Rewoked...' -Component Skype-Function -Type Info
        }
      }
      Else 
      {
        Write-log -Path $log -Message 'Couldn´t open Skype PSSession, try it again...' -Component Skype-Function -Type Error
        Skype-Part
		
        Write-log -Path $log -Message '---------------------------------------' -Component Skype-Function -Type Info
      }
    }
    function Set-FullPermission {
      #Set Full Permission
      $GetACL = Get-Acl $FDR |
      Select-Object -ExpandProperty Access |
      Where-Object -Property identityreference -EQ -Value "$domain\$deputy" |
      Select-Object -ExpandProperty filesystemrights
      if($GetACL -eq 'FullControl')
      {
        Write-log -Path $log -Message "Full Permission already set for: $deputy" -Component ACL-Function -Type Warning
        Write-log -Path $log -Message "Folder Path: $FDR" -Component ACL-Function -Type Info
      }
      Else
      {
        $acl = Get-Acl $FDR
        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ("$domain\$deputy", 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($AccessRule)
        $acl | Set-Acl $FDR
        $GetACL = Get-Acl $FDR |
        Select-Object -ExpandProperty Access |
        Where-Object -Property identityreference -EQ -Value "$domain\$deputy" |
        Select-Object -ExpandProperty filesystemrights
        if ($GetACL -eq 'FullControl') 
        {
          Write-log -Path $log -Message "Full Permission Set for: $deputy" -Component ACL-Function -Type Info
          Write-log -Path $log -Message "Folder Path: $FDR" -Component ACL-Function -Type Info
        }

        else 
        {
          Write-log -Path $log -Message "Full Permission not set for: $deputy" -Component ACL-Function -Type Error
          Write-log -Path $log -Message "Folder Path: $FDR" -Component ACL-Function -Type Info
        }
        Write-log -Path $log -Message '---------------------------------------' -Component ACL-Function -Type Info
      }
    }
    function Del-UserData {
      if (Test-Path $FDR) 
      { 
        Write-log -Path $log -Message 'Deleting User Files, please wait...' -Component DelUserData-Function -Type Warning
        Remove-Item $FDR -Force -Confirm:$False -Recurse
      }

      if (!(Test-Path $FDR)) 
      {
        Write-log -Path $log -Message "User Files deleted: $FDR" -Component DelUserData-Function -Type Info
      }

      else 
      {
        Write-log -Path $log -Message "User Files not deleted: $FDR" -Component DelUserData-Function -Type Warning
      }
      Write-log -Path $log -Message '---------------------------------------' -Component DelUserData-Function -Type Info
    }
    function O365-Part {
      $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($adminUPN, $PW)
      $MSOnline = (Get-InstalledModule -Name Msonline -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Name
      $Azure = (Get-InstalledModule -Name AzureAD -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Name
      $MSGraph = (Get-InstalledModule -Name Microsoft.Graph.Intune -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Name
		
      if (!$MSOnline)
      {
        Install-Module -Name Msonline -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        Write-log -Path $log -Message 'MSOnline Module installed...' -Component O365-Part -Type Info	
      }
		
      if (!$MSGraph)
      {
        Install-Module -Name Microsoft.Graph.Intune -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        Write-log -Path $log -Message 'MSGraph Module installed...' -Component O365-Part -Type Info	
      }
		
      if (!$Azure)
      {
        Install-Module -Name AzureAD -Force -Confirm:$False -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue
        Write-log -Path $log -Message 'AzureAD Module installed...' -Component O365-Part -Type Info	
      }
		
      Import-Module -Name AzureAD -WarningAction SilentlyContinue
      Import-Module -Name Msonline -WarningAction SilentlyContinue
      Import-Module -Name Microsoft.Graph.Intune -WarningAction SilentlyContinue
	
      Write-log -Path $log -Message 'Connect to O365 Services...' -Component O365-Part -Type Info
      Connect-AzureAD -Credential $creds -ErrorVariable AzureADConnectionError -ErrorAction SilentlyContinue
      Connect-MSGraph -PSCredential $creds -ErrorVariable MSGraphConnectionError -ErrorAction SilentlyContinue
      Connect-MsolService -Credential $creds -ErrorVariable MsolServiceConnectionError -ErrorAction SilentlyContinue
			
      if ($AzureADConnectionError)
      {
        Write-log -Path $log -Message 'Can´t Connect to Azure AD Services...' -Component O365-Part -Type Error
      }
      if ($MSGraphConnectionError)
      {
        Write-log -Path $log -Message 'Can´t Connect to MSGraph Services...' -Component O365-Part -Type Error
      }
      if ($MsolServiceConnectionError)
      {
        Write-log -Path $log -Message 'Can´t Connect to MS Online Services...' -Component O365-Part -Type Error
      }
			
      if ((!$MsolServiceConnectionError) -and (!$AzureADConnectionError))
      {
        $cUpn = $User+"@$domain.eu"
        $MsolUser = Get-MsolUser -UserPrincipalName $cUpn -ErrorAction SilentlyContinue
	
        if($MsolUser.BlockCredential -eq $true)
        {
          Write-log -Path $log -Message "$User - SignIn already Blocked..." -Component O365-Part -Type Info
        }
		
        if($MsolUser.BlockCredential -eq $False)
        {
          $MsolUser| Set-MsolUser -BlockCredential $true
          Write-log -Path $log -Message "$User - SignIn Blocked..." -Component O365-Part -Type Info
        }
      }
			
      if ((!$MsolServiceConnectionError) -and (!$MSGraphConnectionError))
      {		
        $cUpn = $User+"@$domain.eu"
        $ObjectId = (Get-MsolUser -UserPrincipalName $cUpn -ErrorAction SilentlyContinue).ObjectId
        $IntuneDevices = Get-IntuneManagedDevice -ErrorAction SilentlyContinue | where userid -eq $ObjectId 
				
        if ($IntuneDevices){
          foreach ($IntuneDevice in $IntuneDevices){
            $managedDeviceName = $intuneDevice.managedDeviceName
            $managedDeviceId = $intuneDevice.managedDeviceId
            Remove-IntunemanagedDevice -managedDeviceId $managedDeviceId -ErrorAction SilentlyContinue -ErrorVariable IntuneDeviceRemove
            if ($IntuneDeviceRemove)
            {
              Write-log -Path $log -Message "Failed to remove Intune Device '$managedDeviceName' ..." -Component O365-Part -Type Error
            }
            Write-log -Path $log -Message "Intune Device '$managedDeviceName' - Removed ..." -Component O365-Part -Type Info
          }
        }
      }
    }
    Function Read-CMLogfile {
      $result = $Null
      $result = @()
      $cmlogformat = $False
      $cmslimlogformat = $False
      # Use .Net function instead of Get-Content, much faster.
      $file = [System.io.File]::Open($log, 'Open', 'Read', 'ReadWrite')
      $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($file)
      [string]$LogFileRaw = $reader.ReadToEnd()
      $reader.Close()
      $file.Close()

      $pattern = 'LOG\[(.*?)\]LOG(.*?)time(.*?)date'
      $patternslim = '\$\$\<(.*?)\>\<thread='
        
      if(([Regex]::Match($LogFileRaw, $pattern)).Success -eq $true)
      {
        $cmlogformat = $true
      }
      elseif(([Regex]::Match($LogFileRaw, $patternslim)).Success -eq $true)
      {
        $cmslimlogformat = $true
      }
        
      If($cmlogformat)
      {
        # Split each Logentry into an array since each entry can span over multiple lines
        $logarray = $LogFileRaw -split '<!'

        foreach($logline in $logarray)
        {
          If($logline)
          {            
            # split Log text and meta data values
            $metadata = $logline -split '><'

            # Clean up Log text by stripping the start and end of each entry
            $logtext = ($metadata[0]).Substring(0,($metadata[0]).Length-6).Substring(5)
            
            # Split metadata into an array
            $metaarray = $metadata[1] -split '"'

            # Rebuild the result into a custom PSObject
            $result += $logtext |Select-Object -Property @{
              Label      = 'LogText'
              Expression = {
                $logtext
              }
            }, @{
              Label      = 'Type'
              Expression = {
                [string][LogType]$metaarray[9]
              }
            }, @{
              Label      = 'Component'
              Expression = {
                $metaarray[5]
              }
            }
          }        
        }
      }

      If($cmslimlogformat)
      {
        # Split each Logentry into an array since each entry can span over multiple lines
        $logarray = $LogFileRaw -split [System.Environment]::NewLine
              
        foreach($logline in $logarray)
        {
          If($logline)
          {
            # split Log text and meta data values
            $metadata = $logline -split '\$\$<'

            # Clean up Log text by stripping the start and end of each entry
            $logtext = $metadata[0]
            
            # Split metadata into an array
            $metaarray = $metadata[1] -split '><'
            If($logtext)
            {
              # Rebuild the result into a custom PSObject
              If($metaarray[1] -match '\+')
              {
                $result += $logtext | Select-Object -Property @{
                  Label      = 'LogText'
                  Expression = {
                    $logtext
                  }
                }, @{
                  Label      = 'Type'
                  Expression = {
                    [LogType]0
                  }
                }, @{
                  Label      = 'Component'
                  Expression = {
                    $metaarray[0]
                  }
                }
              }
              else
              {
                $result += $logtext |Select-Object -Property @{
                  Label      = 'LogText'
                  Expression = {
                    $logtext
                  }
                }, @{
                  Label      = 'Type'
                  Expression = {
                    [LogType]0
                  }
                }, @{
                  Label      = 'Component'
                  Expression = {
                    $metaarray[0]
                  }
                }
              }
            }
          }
        }
      }
    

    
      $result #return data
    }
		
    #The base DN for accounts (DC=appanoxstudios,DC=com)
    $dn = $domainSVar.DistinguishedName 

    #The domain (appanoxstudios.com) 
    $dnsroot = $domainSVar.DNSRoot 

    # Allow TextChanged on user's selection from list
    $selectionChangedSatus = $False
    #==============================================================================================
    # XAML Code
    #==============================================================================================
    $inputXML = @"
<Window x:Class="ADULive.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:EmployeeEntry"
        mc:Ignorable="d"
        
				Title="Employee Entry" Height="320" Width="400" WindowStartupLocation="CenterScreen" WindowStyle='None' ResizeMode='NoResize'>
        <Grid Margin="0,0,-0.2,0.2">
				<Label x:Name="searchLabel" Content="Search Exit User" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0,27,0,0"  Height="30" Width="170" Background="green" Foreground="White" />
            <StackPanel Canvas.ZIndex="3">
						<TextBox x:Name="exitUser" HorizontalAlignment="Left" Height="30" Margin="175,27,0,0" TextWrapping="Wrap" Text=""  Width="200" IsEnabled="True"/>
            <Border x:Name="exitUserListBorder" BorderBrush="#f3f3f3" Margin="175,0,0,0" Visibility="Collapsed "
							 BorderThickness="1" MinWidth="170">
             <ListBox  Foreground="Black"  MaxHeight="150" x:Name="exitUserList" ScrollViewer.HorizontalScrollBarVisibility="Disabled"  ScrollViewer.VerticalScrollBarVisibility="Auto" DisplayMemberPath="{Binding}">
								<ListBox.ItemTemplate>
                  <DataTemplate>
                      <TextBlock Text="{Binding ItemData}" TextWrapping="Wrap" FontWeight="Normal" />
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
             </Border>
	</StackPanel>
				<Label x:Name="searchLabel2" Content="Search Representative User" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0,62,0,0"  Height="30" Width="170" Background="darkorange" Foreground="White" />
            <StackPanel Canvas.ZIndex="2">
						<TextBox x:Name="deputyUser" HorizontalAlignment="Left" Height="30" Margin="175,62,0,0" TextWrapping="Wrap" Text=""  Width="200" IsEnabled="True"/>
            <Border x:Name="deputyUserListBorder" BorderBrush="#f3f3f3" Margin="175,0,0,0" Visibility="Collapsed "
							 BorderThickness="1" MinWidth="170">
             <ListBox  Foreground="Black"  MaxHeight="150" x:Name="deputyUserList" ScrollViewer.HorizontalScrollBarVisibility="Disabled"  ScrollViewer.VerticalScrollBarVisibility="Auto" DisplayMemberPath="{Binding}">
								<ListBox.ItemTemplate>
                  <DataTemplate>
                      <TextBlock Text="{Binding ItemData}" TextWrapping="Wrap" FontWeight="Normal" />
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
             </Border>
	</StackPanel>
        <TextBox HorizontalAlignment="Center" Height="23" TextWrapping="Wrap" Text="Employee Exit" VerticalAlignment="Top" Width="400" Margin="0,-1,-0.2,0" TextAlignment="Center" Foreground="White" Background="DarkBlue"/>
        <Label Content="Employee Name" HorizontalAlignment="Left" Margin="0,102,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="LightBlue" Foreground="White"/>
        <Label Content="Representative" HorizontalAlignment="Left" Margin="0,137,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="LightBlue" Foreground="White"/>
        <Label Content="Ticket Number" HorizontalAlignment="Left" Margin="0,172,0,0" VerticalAlignment="Top" Height="30" Width="170" Background="LightBlue" Foreground="White"/>
        <Button x:Name="okButton" Content="OK" HorizontalAlignment="Left" Margin="0,300,0,0" VerticalAlignment="Top" Width="200" BorderThickness="0" IsDefault="true"/>
        <Button x:Name="cancelButton" Content="Cancel" HorizontalAlignment="Right" Margin="0,300,0,0" VerticalAlignment="Top" Width="200" BorderThickness="0" IsCancel="True"/>
        <TextBox x:Name="User" HorizontalAlignment="Left" Height="30" Margin="175,102,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <TextBox x:Name="deputy" HorizontalAlignment="Left" Height="30" Margin="175,137,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <TextBox x:Name="TicketNumber" HorizontalAlignment="Left" Height="30" Margin="175,172,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="200" IsEnabled="True"/>
        <CheckBox x:Name="ExpMailbox" Content = 'Export Mailbox' HorizontalAlignment="Left" Margin="0,212,0,0" VerticalAlignment="Top" Height="30" Width="170"/>
        <CheckBox x:Name="DisMailbox" Content = 'Disable Mailbox' HorizontalAlignment="Left" Margin="0,232,0,0" VerticalAlignment="Top" Height="30" Width="170"/>
        <CheckBox x:Name="ArUserData" Content = 'Archive User Data and Set Full Permission' HorizontalAlignment="Left" Margin="0,252,0,0" VerticalAlignment="Top" Height="30" Width="250"/>
        <CheckBox x:Name="DelUserData" Content = 'Delete User Data' HorizontalAlignment="Left" Margin="0,272,0,0" VerticalAlignment="Top" Height="30" Width="170"/>	
    </Grid>
</Window>
"@       
 
    $inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace 'x:N', 'N'  -replace '^<Win.*', '<Window'
 
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]$XAML = $inputXML

    #Read XAML
    $reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML) 
    try
    {
      $Form = [Windows.Markup.XamlReader]::Load( $reader )
    }
    catch
    {
      Write-Host -Object 'Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed.'
    }

    #===========================================================================
    # Store Form Objects In PowerShell
    #===========================================================================
    $XAML.SelectNodes('//*[@Name]') | ForEach-Object -Process {
      Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)
    }

    #===========================================================================
    # Add events to Form Objects
    #===========================================================================
    #Exit User
    $exitUser.Add_TextChanged({
        $exitUserList.Items.Clear()
        #Check for a non-empty list selection
        if($selectionChangedSatus -eq $False -and $selectionChangedSatus -ne $Null -and $exitUser.Text -ne '')
        {
          $QryAllCmd = Get-ADUser -Filter "SamAccountName -like '*$($exitUser.Text)*' -or Name -like '*$($exitUser.Text)*'"  -Properties SamAccountName, Name | Select-Object -Property SamAccountName, Name
          #If user exist in Active Directory then show $WPFexitUserListBorder and populate $WPFexitUserList
          if($QryAllCmd -ne $Null)
          {
            #Add Items to Live Search List
            $exitUserList.Dispatcher.Invoke('Background',[action]{ 
                $QryAllCmd | ForEach-Object -Process {
                  $exitUserList.Items.Add([PSCustomObject]@{
                      'ItemData' = "$($_.Name)"
                  })
                }
            })
            $exitUserListBorder.Visibility = 'Visible'
          }
          else
          {
            $exitUserListBorder.Visibility = 'hidden'
            $exitUserList.Items.Add([PSCustomObject]@{
                'ItemData' = "Your search - '$($exitUser.Text)' - did not match any documents."
            })
          }
        }
        elseif($exitUser.Text -eq '')
        {
          $exitUserListBorder.Visibility = 'hidden'
        }
        else
        {
          #Set $selectionChangedSatus to false when TextChanged occur from SelectionChanged
          $selectionChangedSatus = $False
        }
    })

    $exitUserList.Add_SelectionChanged({
        if($selectionChangedSatus -eq $False)
        {
          #Control selectionChangedSatus
          $selectionChangedSatus = $true
          $exitUserListBorder.Visibility = 'hidden'
          $ou = $Null
    
          #Get SelectedItem from $WPFexitUserList - Data Binding 
          $searcSelectedItem = $exitUserList.SelectedItem 
          $searcSelectedItem |
          Select-Object -Property ItemData |
          ForEach-Object -Process {
            $exitUser.Text = $_.ItemData
          }
        }
        #Defualt Section 
        $userProperties = Get-ADUser -Filter "Name -eq '$($exitUser.Text)'" -Properties SamAccountName, Name | Select-Object -Property SamAccountName, Name
        $User.Text = $userProperties.SamAccountName
    })
		
    #Deputy User
    $deputyUser.Add_TextChanged({
        $deputyUserList.Items.Clear()
        #Check for a non-empty list selection
        if($selectionChangedSatus -eq $False -and $selectionChangedSatus -ne $Null -and $deputyUser.Text -ne '')
        {
          $QryAllCmd = Get-ADUser -Filter "SamAccountName -like '*$($deputyUser.Text)*' -or Name -like '*$($deputyUser.Text)*'"  -Properties SamAccountName, Name | Select-Object -Property SamAccountName, Name
          #If user exist in Active Directory then show $WPFdeputyUserListBorder and populate $WPFdeputyUserList
          if($QryAllCmd -ne $Null)
          {
            #Add Items to Live Search List
            $deputyUserList.Dispatcher.Invoke('Background',[action]{ 
                $QryAllCmd | ForEach-Object -Process {
                  $deputyUserList.Items.Add([PSCustomObject]@{
                      'ItemData' = "$($_.Name)"
                  })
                }
            })
            $deputyUserListBorder.Visibility = 'Visible'
          }
          else
          {
            $deputyUserListBorder.Visibility = 'hidden'
            $deputyUserList.Items.Add([PSCustomObject]@{
                'ItemData' = "Your search - '$($deputyUser.Text)' - did not match any documents."
            })
          }
        }
        elseif($deputyUser.Text -eq '')
        {
          $deputyUserListBorder.Visibility = 'hidden'
        }
        else
        {
          #Set $selectionChangedSatus to false when TextChanged occur from SelectionChanged
          $selectionChangedSatus = $False
        }
    })

    $deputyUserList.Add_SelectionChanged({
        if($selectionChangedSatus -eq $False)
        {
          #Control selectionChangedSatus
          $selectionChangedSatus = $true
          $deputyUserListBorder.Visibility = 'hidden'
          $ou = $Null
    
          #Get SelectedItem from $WPFdeputyUserList - Data Binding 
          $searcSelectedItem = $deputyUserList.SelectedItem 
          $searcSelectedItem |
          Select-Object -Property ItemData |
          ForEach-Object -Process {
            $deputyUser.Text = $_.ItemData
          }
        }
        #Defualt Section 
        $deputyProperties = Get-ADUser -Filter "Name -eq '$($deputyUser.Text)'" -Properties SamAccountName, Name | Select-Object -Property SamAccountName, Name
        $deputy.Text = $deputyProperties.SamAccountName
    })
		
    $cancelButton.Add_Click({
        $Form.DialogResult = $False
    })
    $okButton.Add_Click({
        $Form.DialogResult = $true
    })
		
		
		
    #===========================================================================
    # Shows the form
    #===========================================================================
    $result = $Form.ShowDialog() #| Out-Null
		
    #######################################################Start the Script/Functions#################################################
    if ($result -eq $true)
    {
      #######################################################Variables##################################################################

      #GUI Values
      $User = if ($User.Text) 
      {
        $User.Text
      }
      $deputy = if ($deputy.Text) 
      {
        $deputy.Text
      }
      $TicketNumber = if ($TicketNumber.Text) 
      {
        $TicketNumber.Text
      }
      if ($ExpMailbox.IsChecked -eq $true) 
      {
        $ArMailbox = $true
      }
      Else 
      {
        $ArMailbox = $False
      }
      if ($DisMailbox.IsChecked -eq $true) 
      {
        $DisMailbox = $true
      }
      Else 
      {
        $DisMailbox = $False
      }
      if ($ArUserData.IsChecked -eq $true) 
      {
        $ArUserData = $true
      }
      Else 
      {
        $ArUserData = $False
      }
      if ($DelUserData.IsChecked -eq $true) 
      {
        $DelUserData = $true
      }
      Else 
      {
        $DelUserData = $False
      }

      #######################################################################################################
      ######################################Please Edit all Variables!#######################################
      #######################################################################################################
      $Version = 'v1.1'
      $Date = Get-Date -Format yyyyMMdd
      $log = "$env:LOCALAPPDATA\EmployeeExit_$User" + "_$Date.log"
      $LogLevel = 'None'

      #Remove Old Log File
      if (Test-Path $log) 
      {
        Remove-Item $log -Force -Confirm:$False
        Write-log -Path $log -Message 'Old Logfile removed...' -Component Script-Information -Type Warning
      }

      Write-log -Path $log -Message "Employee Exit Script - $Version" -Component Script-Information -Type Info
      Write-log -Path $log -Message "Script started from, $env:USERNAME" -Component Script-Information -Type Info
      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info

      #Find Domain
      $Location = (Get-ADUser $User).distinguishedName.Split(',')[-4].Split('=')[1] #In my Case its the Location from User based on AD OU + Server Naming
      $Retired = (Get-ADUser $User).distinguishedName.Split(',')[-3].Split('=')[1]

      #Folderredirection
      $ServerName = 'xxxxxxxxxxxxxxxxxxxxxxx' #ServerName where User Files are stored
      $FDR = "$ServerName\user\$User" #Full path to user Files (for Zipping and Fullpermission)
      #Archive
      $ArchiveServer = 'xxxxxxxxxxxxxxxxxxxxxxx'
      $UserPath = "$ArchiveServer\bdarchive$\UserData\"
      #AD
      $domain = (Get-WmiObject -Class win32_computersystem).Domain.split('.')[0]
      $UserDN = (Get-ADUser $User).DistinguishedName
      $RetiredOU = $UserDN.split(',')[-4].split('=')[1]
      $RetiredOUDN = "OU=$RetiredOU,OU=Retired,DC=$domain,DC=LOCAL"
      #Exchange
      $Path = $ArchiveServer+'\bdarchive$\PST\'+ $User + '_' + $Date + '.pst' #Path where PST Export should be stored
      $Exchange = "xxxxxxxxxxxxxxxxxxxxxxx" #Exchange Server for invoke command (archive Mailbox, setting full permission)
      $BatchName = "Export_$User-$TicketNumber"
      $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$Exchange/powershell
      #Skype
      $SkypeID = $domain+'\'+$User
      $aduser = Get-ADUser $User
      $Skype = "xxxxxxxxxxxxxxxxxxxxxxx" #Skype Server for invoke Command

      #Mail
      $from = "xxxxxxxxxxxxxxxxxxxxxxx"
      $to = "xxxxxxxxxxxxxxxxxxxxxxx"
      $tocrm = "xxxxxxxxxxxxxxxxxxxxxxx"
      $toKix = "xxxxxxxxxxxxxxxxxxxxxxx"
      $SMTP = "xxxxxxxxxxxxxxxxxxxxxxx"
      #Tools
      $cmtrace = 'xxxxxxxxxxxxxxxxxxxxxxx' #Path to CMtrace.exe
      #O365
      $adminUPN = 'xxxxxxxxxxxxxxxxxxxxxxx' #Global Admin or a User that can make desired Changes, you also can edit this step with Get Credential on Line: 475 (then you have to delete this variable from here)
      $PW = 'xxxxxxxxxxxxxxxxxxxxxxx' | ConvertTo-SecureString -Key (1..16) #Encrypted Password, you also can edit this step with Get Credential on Line: 475 (then you have to delete this variable from here)

      #######################################################################################################
      #########################################Adjust Variables END!#########################################
      #######################################################################################################


      #######################################################Run the Script/Functions##################################################
      & $cmtrace $log
      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info
      Write-log -Path $log -Message 'Script Input Parameter...' -Component Script-Information -Type Info
      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info

      Write-log -Path $log -Message "User: $User" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Deputy: $deputy" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Standort: $Location" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Ticketnumber: $TicketNumber" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Export Mailbox: $ArMailbox" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Disable Mailbox: $DisMailbox" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Archive User Data: $ArUserData" -Component Script-InputData -Type Info
      Write-log -Path $log -Message "Delete User Data: $DelUserData" -Component Script-InputData -Type Info
      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info
			
      #Import Required Modules
      Import-Module -Name PoshProgressBar -ErrorAction SilentlyContinue
      Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
			
      #AD/Skype/Exchange	
      if ($result -eq 'OK' -and $User) 
      {
        AD-Part
        O365-Part
        Exchange-Part
        Skype-Part		
      }


      #Zip User Files and Set Full Permission

      if ($ArUserData -eq $true) 
      {
        $TestFDR = Test-Path $FDR

        if ($TestFDR -eq $true) 
        {	
          $name = "$User" + '_' + "$Date" + '.zip'
          $source = $FDR
          $destination = $UserPath+$name
          $7zipPath = '\\xxxxxxxxxxxxxxxxxxxxxxx\7z.exe' #Patch to '7-Zip: 7z.exe' (for File Zipping)
          $7zipParam = "a -mx=5 $destination $source"
          $FolderSize = '{0:N2} MB' -f ((Get-ChildItem $source -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
          If(Test-Path $destination) 
          {
            Write-log -Path $log -Message 'Zip file already present, removing Zip File...' -Component Zip-Function -Type Warning
            Remove-Item $destination
          }

          Write-log -Path $log -Message 'Zipping Files Started' -Component Zip-Function -Type Info
          Write-log -Path $log -Message "Folder Size: $FolderSize" -Component Zip-Function -Type Info
          Write-log -Path $log -Message 'Zipping currently in progress, please wait...' -Component Zip-Function -Type Info
					 
          if (Test-Path -Path $7zipPath) 
          {
            $ZipProcess = Start-Process $7zipPath -ArgumentList $7zipParam -PassThru -WindowStyle Hidden
            $ZipProgressBar = New-ProgressBar -MaterialDesign -Type Horizontal -PrimaryColor LightBlue -AccentColor Blue -Size Large -Theme Dark

            for($i = 0; $i -le 100; $i = ($i + 1) % 100)
            {
              Write-ProgressBar -ProgressBar $ZipProgressBar -Activity 'Zipping Files' -PercentComplete $i -CurrentOperation "Zipping to: $($destination)"														
              Start-Sleep -Milliseconds 100
              if ($ZipProcess.HasExited) 
              {
                break
              }
            }
            Close-ProgressBar -ProgressBar $ZipProgressBar											
          }
          Write-log -Path $log -Message "User Files Zipped to: $destination" -Component Zip-Function -Type Info
          Write-log -Path $log -Message '---------------------------------------' -Component Zip-Function -Type Info	

          if ($deputy)
          {
            Set-FullPermission
          }
        }
        if ($TestFDR -eq $False) 
        {
          Write-log -Path $log -Message '---------------------------------------' -Component ArchiveUserData -Type Info
          Write-log -Path $log -Message "No User Files found, can't Zip..." -Component ArchiveUserData -Type Warning
          Write-log -Path $log -Message '---------------------------------------' -Component ArchiveUserData -Type Info
        }  
      }
  
      if ($ArUserData -ne $true) 
      {
        Write-log -Path $log -Message 'Archive User Data not Checked...' -Component ArchiveUserData -Type Info
        Write-log -Path $log -Message '---------------------------------------' -Component ArchiveUserData -Type Info
      }

      #Delte User Files
      if ($DelUserData -eq $true)
      {
        $TestFDR = Test-Path $FDR

        if ($TestFDR -eq $true) 
        {
          Del-UserData
        }

        if ($TestFDR -eq $False) 
        {
          Write-log -Path $log -Message "No User Files found, can't delete..." -Component DelteUserData -Type Warning
          Write-log -Path $log -Message '---------------------------------------' -Component DelteUserData -Type Info
        }  
      }
      if ($DelUserData -ne $true)
      {
        Write-log -Path $log -Message 'Delete User Data not Checked...' -Component DelteUserData -Type Info
        Write-log -Path $log -Message '---------------------------------------' -Component DelteUserData -Type Info
      }

      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info
      Write-log -Path $log -Message 'Employee Exit Script finished...' -Component Script-Information -Type Info
      Write-log -Path $log -Message '---------------------------------------' -Component Script-Information -Type Info
      Write-log -Path $log -Message 'If Ticketnumber entered, Log content will be sent to Ticketsystem...' -Component Script-Information -Type Info
      Write-log -Path $log -Message "If User has a CRM Account a mail will be sent to $tocrm, for further tasks (deactivate...)..." -Component Script-Information -Type Info

      if ($TicketNumber) 
      {
        if (($TicketNumber.Length -eq '13') -and ($TicketNumber -match '-')){
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

          $Body = Read-CMLogfile |
          Where-Object -FilterScript {
            $_.Type -ge ([LogType]::($LogLevel).value__)
          } |
          Format-Table -AutoSize | Out-String  
          $Body = '<pre>{0}</pre>' -f [System.Net.WebUtility]::HtmlEncode($Body)
					
          Send-MailMessage -To $to -From $from -Subject "[#$TicketNumber]" -SmtpServer $SMTP -Body $Body -BodyAsHtml 
        }
        if ($TicketNumber.Length -ge '15'){
				
          #Build Subject
          if (($TicketNumber.Length -eq '15') -and ($TicketNumber -inotmatch '-' -or $TicketNumber -inotmatch 'M#')){$TicketNumber = 'M#'+$TicketNumber}
          if (($TicketNumber.Length -eq '17') -and ($TicketNumber -match 'M#')){$TicketNumber = $TicketNumber}
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

          $Body = Read-CMLogfile |
          Where-Object -FilterScript {
            $_.Type -ge ([LogType]::($LogLevel).value__)
          } |
          Format-Table -AutoSize | Out-String
          $Body = '<pre>{0}</pre>' -f [System.Net.WebUtility]::HtmlEncode($Body)
					
          Send-MailMessage -To $toKix -From $from -Subject "[$TicketNumber]" -SmtpServer $SMTP -Body $Body -BodyAsHtml 
        }
      }
			
      $Groups = Get-ADPrincipalGroupMembership -Identity $User
      if ($groups.Name -like 'ReportingGroup {*'){$CRMUser = $true}
			
      if ($CRMUser)
      {
        $CRMBodyComp += '<p><span style="color: #508080;">' + $user + "</span></p>"
        $CRMBodyComp += '<p><span style="color: #607080;">' + "Ticket: $TicketNumber" + "</span></p>"

        $CRMMailtemplate = @"
				<h3><span style="color: #808080;">Please deactivate CRM User:</span></h3>
				<h4><span style="color: #508080;">$CRMBodyComp</span></h4>
				<h2>&nbsp;</h2>
"@
        Send-MailMessage -To $tocrm -From $from -Subject "Employee Exit - $User" -SmtpServer $SMTP -Body $CRMMailtemplate -BodyAsHtml
      }
    }
    Else 
    {
      Exit
    }
})
#Thread Synchronization
$psCmdADUL.Runspace = $newRunspaceADUL
$data = $psCmdADUL.BeginInvoke()
