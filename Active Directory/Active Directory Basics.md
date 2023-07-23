# Introduction
- Microsoft's Active Directory is the backbone of the corporate world. It simplifies the management of devices and users within a corporate environment
# Windows Domins
- a Windows domain is a group of users and computers under the administration of a given business. The main idea behind a domain is to centralise the administration of common components of a Windows computer network in a single repository called Active Directory (AD)
- The server that runs the Active Directory services is known as a Domain Controller (DC).
![DomainC](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/dom.png)
- advantages of having a configured Windows domain are :
  - Centralised identity management: All users across the network can be configured from Active Directory with minimum effort
  - Managing security policies: You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.
# Active Directory
- The core of any Windows Domain is the Active Directory Domain Service (AD DS)
- Amongst the many objects supported by AD, we have users, groups, machines, printers, shares and many others. Let's look at some of them
- Users are one of the most common object types in Active Directory. Users are one of the objects known as security principals, meaning that they can be authenticated by the domain and can be assigned privileges over resources like files or printers
- security principal is an object that can act upon resources in the network
- Users can be used to represent two types of entities :
  - People: users will generally represent persons in your organisation that need to access the network, like employees
  - Services: you can also define users to be used by services like IIS or MSSQL. Every single service requires a user to run, but service users are different from regular users as they will only have the privileges needed to run their specific service.
- Machines are another type of object within Active Directory; for every computer that joins the Active Directory domain, a machine object will be created. Machines are also considered "security principals" and are assigned an account just as any regular user. This account has somewhat limited rights within the domain itself
- The machine accounts themselves are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in
- Machine Account passwords are automatically rotated out and are generally comprised of 120 random characters
- The machine account name is the computer's name followed by a dollar sign
- a machine named DC01 will have a machine account called DC01$
- you can define user groups to assign access rights to files or other resources to entire groups instead of single users. This allows for better manageability as you can add users to an existing group
- Groups can have both users and machines as members. If needed, groups can include other groups as well
- Several groups are created by default in a domain that can be used to grant specific privileges to users

![security groups](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/sec.jpeg)
- To configure users, groups or machines in Active Directory, we need to log in to the Domain Controller and run "Active Directory Users and Computers" from the start menu:
  
![security groups1](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/sec1.png)
- open up a window where you can see the hierarchy of users, computers and groups that exist in the domain. These objects are organised in Organizational Units (OUs) which are container objects that allow you to classify users and machines. OUs are mainly used to define sets of users with similar policing requirements
-  people in the Sales department of your organisation are likely to have a different set of policies applied than the people in IT
-  a user can only be a part of a single OU at a time
- there are default containers
  - Builtin: Contains default groups available to any Windows host.
  - Computers: Any machine joining the network will be put here by default. You can move them if needed.
  - Domain Controllers: Default OU that contains the DCs in your network.
  - Users: Default users and groups that apply to a domain-wide context.
  - Managed Service Accounts: Holds accounts used by services in your Windows domain.
- groups and OUs. While both are used to classify users and computers, their purposes are entirely different
  - OUs are handy for applying policies to users and computers, which include specific configurations that pertain to sets of users depending on their 
    particular role in the enterprise. Remember, a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different 
    sets of policies to a single user
  - Security Groups, on the other hand, are used to grant permissions over resources. For example, you will use groups if you want to allow some users to 
    access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources
# Managing Users in AD
- to give specific users some control over some OUs. This process is known as delegation and allows you to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Administrator to step in
-  to do password resets. In this case, we will be using Powershell to do so
  - **Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose**
- since we wouldn't want Sophie to keep on using a password we know, we can also force a password reset at the next logon with the following command
  - **Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose**
# Managing Computers in AD
- By default, all the machines that join a domain (except for the DCs) will be put in the container called "Computers"
- Workstations
  - Workstations are one of the most common devices within an Active Directory domain. Each user in the domain will likely be logging into a workstation. This 
    is the device they will use to do their work or normal browsing activities. These devices should never have a privileged user signed into them
- Servers
  - Servers are the second most common device within an Active Directory domain. Servers are generally used to provide services to users or other servers
- Domain Controllers
  - Domain Controllers are the third most common device within an Active Directory domain. Domain Controllers allow you to manage the Active Directory Domain. 
    These devices are often deemed the most sensitive devices within the network as they contain hashed passwords for all user accounts within the environment
# Group Policies
- Group Policy Objects (GPO). GPOs are simply a collection of settings that can be applied to OUs. GPOs can contain policies aimed at either users or computers, allowing you to set a baseline on specific machines and identities
- To configure GPOs, you can use the Group Policy Management tool
- To configure Group Policies, you first create a GPO under Group Policy Objects and then link it to the GPO where you want the policies to apply
- GPOs are distributed to the network via a network share called SYSVOL
- which is stored in the DC. All users in a domain should typically have access to this share over the network to sync their GPOs periodically
- The SYSVOL share points by default to the C:\Windows\SYSVOL\sysvol\ directory on each of the DCs in our network
- Once a change has been made to any GPOs, it might take up to 2 hours for computers to catch up. If you want to force any particular computer to sync its GPOs immediately,---> **gpupdate /force**
# Authentication Methods
- When using Windows domains, all credentials are stored in the Domain Controllers
- Whenever a user tries to authenticate to a service using domain credentials, the service will need to ask the Domain Controller to verify if they are correct
- Two protocols can be used for network authentication in windows domains
  - Kerberos: Used by any recent version of Windows. This is the default protocol in any recent domain
  - NetNTLM: Legacy authentication protocol kept for compatibility purposes
- most networks will have both protocols enabled
- Kerberos Authentication
  - The user sends their username and a timestamp encrypted using a key derived from their password to the Key Distribution Center (KDC) ( a service usually installed on the Domain 
    Controller in charge of creating Kerberos tickets on the network)
  - The KDC will create and send back a Ticket Granting Ticket (TGT), which will allow the user to request additional tickets to access specific services
  -  Along with the TGT, a Session Key is given to the user, which they will need to generate the following requests
  -  the TGT is encrypted using the krbtgt account's password hash, and therefore the user can't access its contents
  -  It is essential to know that the encrypted TGT includes a copy of the Session Key as part of its contents
  -  and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed
![kerb](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/kerb.png)
 
- When a user wants to connect to a service on the network like a share, website or database, they will use their TGT to ask the KDC for a Ticket Granting Service (TGS)
  -  TGS are tickets that allow connection only to the specific service they were created for.
  -  To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with the TGT and a Service Principal Name (SPN)
  -  which indicates the service and server name we intend to access
  -  As a result, the KDC will send us a TGS along with a Service Session Key, which we will need to authenticate to the service we want to access
  -  The TGS is encrypted using a key derived from the Service Owner Hash
     - The Service Owner is the user or machine account that the service runs under
  - The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS
![tgs](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/tgs.png)

  - The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key

![tgs2](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/tgs2.png)

- NetNTLM Authentication
  - NetNTLM works using a challenge-response mechanism
![ntlm](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/ntlm.png)
