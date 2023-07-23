# Introduction
- Microsoft's Active Directory is the backbone of the corporate world. It simplifies the management of devices and users within a corporate environment
# windows Doamins
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

