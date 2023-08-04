# Physical Active Directory
- The physical Active Directory is the servers and machines on-premise
- can be anything from domain controllers and storage servers to domain user machines; everything needed for an Active Directory environment besides the software
- Domain Controllers
  - Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest
  - Domain controllers are the center of Active Directory -- they control the rest of the domain
  - holds the AD DS data store
  - handles authentication and authorization services
  - replicate updates from other domain controllers in the forest
  - Allows admin access to manage domain resources
- AD DS Data Store
  - holds the databases and processes needed to store and manage directory information such as users, groups, and services.
  - Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
  - Stored by default in %SystemRoot%\NTDS
  - accessible only by the domain controller
# The Forest
- collection of one or more domain trees inside of an Active Directory network. It is what categorizes the parts of the network as a whole
- The Forest consists of :
  - Trees - A hierarchy of domains in Active Directory Domain Services
  - Domains - Used to group and manage objects
  - Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
  - Trusts - Allows users to access resources in other domains
  - Objects - users, groups, printers, computers, shares
  - Domain Services - DNS Server, LLMNR, IPv6
  - Domain Schema - Rules for object creation
# Users + Groups
