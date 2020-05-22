ActiveDirectory Module is Required.

    Adjust Code on Line 434 -  488

GUI Looks Like this:

![alt text](https://raw.githubusercontent.com/FSCorrupt/PS-Employee-Exit-Script/master/gui%20(1).png)



Mail Body looks like this:

![alt text](https://raw.githubusercontent.com/FSCorrupt/PS-Employee-Exit-Script/master/Untitled.png)



Feature List:
    
    Downloading CMTrace for Log viewing if its not present.
    Disable AD Account
    Remove all Groups (except domain users)
    Clear user Attribute (Telephone, manager, mobile, facsimile)
    Move to Retired OU
    Set Full permission to Mailbox for the User Deputy
    Archive and or Delete User Mailbox
    Remove Skype User
    Revoke CS Client Certs
    Set Full permission to my documents for the User Deputy
    Zipping those files to an Archive share
    Delete User Files
    Formats Log File to a readable Mail Body
    Sending mail to Ticket System with Log Output
    Read-CMTrace LogFile Function
