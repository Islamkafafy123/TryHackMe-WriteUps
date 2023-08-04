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
- Users are the core to Active Directory
- The four types of users are:
  - Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
  - Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
  - Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
  - Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

- ﻿Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions
- types of Active Directory groups:
  - Security Groups - These groups are used to specify permissions for a large number of users
  - Distribution Groups - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration

# Trusts + Policies
- go hand in hand to help the domain and trees communicate with each other and maintain "security" inside of the network
- They put the rules in place of how the domains inside of a forest can interact with each other, how an external forest can interact with the forest, and the overall domain rules or policies that a domain must follow
- two types of trusts :
  - Directional - The direction of the trust flows from a trusting domain to a trusted domain
  - transitive - The trust relationship expands beyond just two domains to include other trusted domains

# Active Directory Domain Services + Authentication
- Domain Services are services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller
- default domain services:
  - LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
  - Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
  - DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames
- Domain Authentication :
  - Kerberos - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain
  - NTLM - default Windows authentication protocol uses an encrypted challenge/response protocol

# AD in the Cloud
- Azure AD Overview
  - Azure acts as the middle man between your physical Active Directory and your users' sign on. This allows for a more secure transaction between domains, making a lot of Active Directory attacks ineffective
- Cloud Security Overview
![cloud](https://github.com/Islamkafafy123/TryHackMe-WriteUps/blob/main/Pictures/cloud.jpeg)
