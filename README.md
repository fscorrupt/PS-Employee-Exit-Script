Modules Required:

    ActiveDirectory Module is Required. (Install-Module -Name ActiveDirectory -Force)
    PoshProgressBar Module is Required. (Install-Module -Name PoshProgressBar -Force)

Code Adjust:

    Adjust Code on Line 999 -  1057

GUI Looks Like this:

![alt text](https://i.imgur.com/9rTB2Fv.png)



Mail Body/Log looks like this:

![alt text](https://raw.githubusercontent.com/FSCorrupt/PS-Employee-Exit-Script/master/Untitled.png)



Feature List:

   Gui Feature:
   
    Live Search in AD for deputyUser and exitUser

   ADPart:
   
    Disable AD Account
    Remove all Groups and add user to Domain Guests
    Clear user Attribute (Telephone, manager, mobile, facsimile, Primary Computer......)
    Move to Retired OU
    
   Exchange Part:
   
    Set Full permission to Mailbox for the User Deputy
    Hide user from AdressBook
    Remove User Picture
    Remove Active Sync Devices
    Archive and or Delete User Mailbox
    
   Skype4Business Part:
   
    Remove Skype User
    Revoke CS Client Certs
    
   User Files Part:
   
    Set Full permission to my documents for the User Deputy
    Zipping those files to an Archive share
    Delete User Files
    
   O365 Part:
   
    Disable Sign-In in O365
    
   Formatting and Logging Part:
   
    Formats Log File to a readable Mail Body
    Sending mail to Ticket System with Log Output
    Read-CMTrace LogFile Function
