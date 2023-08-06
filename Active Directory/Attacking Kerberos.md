# Introdution
- Kerberos is the default authentication service for Microsoft Windows domains
- intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption
- NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage
- Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service
- Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets
- Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain
- Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set
- KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC
- Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key
- Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC
- Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket
- Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the use4
- AS-REQ w/ Pre-Authentication
  - The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC.
  - to validate the user and create a TGT for the user, the KDC must follow
    - encrypt a timestamp NT hash and send it to the AS
    - The KDC attempts to decrypt the timestamp using the NT hash from the user
    -  if successful the KDC will issue a TGT as well as a session key for the user
- the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket
- A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.
  - Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash
  - User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key
- Kerberos Authentication
  - AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT)
  - AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT
  - TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access
  - TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client
  - AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access
  - AP-REP - 6.) The service grants access
- Kerberos Tickets
  - The main ticket that you will see is a ticket-granting ticket these can come in various forms such as a .kirbi for Rubeus .ccache for Impacket
  - A ticket is typically base64 encoded and can be used for various attacks ,The ticket-granting ticket is only used with the KDC in order to get service tickets
  - Once you give the TGT the server then gets the User details, session key, and then encrypts the ticket with the service account NTLM hash
  - Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT
  - The KDC will then authenticate the TGT and give back a service ticket for the requested service
  - normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you to get any service ticket that you want allowing you to access anything on the domain that you want
# Enumeration w/ Kerbrute
- By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams
- When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist
```
./TOOLS/kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local /home/kali/TOOLS/Active-Directory-Wordlists/User.txt
```
# Harvesting & Brute-Forcing Tickets w/ Rubeus
```
Rubeus.exe harvest /interval:30 - This command tells Rubeus to harvest for TGTs every 30 seconds
```
- Brute-Forcing / Password-Spraying w/ Rubeus
  - Rubeus can both brute force passwords as well as password spray user accounts
  - When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account
  - In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password
  ```
  Rubeus.exe brute /password:Password1 /noticket - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user
  ```
# Kerberoasting w/ Rubeus & Impacket
- Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password
- If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is
- To enumerate Kerberoastable accounts use BloodHound to find all Kerberoastable account
```
Kerberoasting w/ Rubeus - 

1.) cd Downloads - navigate to the directory Rubeus is in

2.) Rubeus.exe kerberoast This will dump the Kerberos hash of any kerberoastable users
```
- copy the 2 hashes
```
hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash ---- > MYPassword123#
```

```
Kerberoasting w/ Impacket - 

1.) cd /usr/share/doc/python3-impacket/examples/ - navigate to where GetUserSPNs.py is located

2.) sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.138.185 -request - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash
```

- What Can a Service Account do?
  - After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not
  - If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit
  - If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts

- Kerberoasting Mitigation
  - Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
  - Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.

# AS-REP Roasting w/ Rubeus
- AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled
- users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled
- During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used
- After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT
- can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are

```
Rubeus.exe asreproast - This will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.
insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....
hashcat -m 18200 hash.txt Pass.txt - crack those hashes! Rubeus AS-REP Roasting uses hashcat mode 18200 
```
- AS-REP Roasting Mitigations
  - Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
  - Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

# Pass the Ticket w/ mimikatz
- Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however we'll be using mimikatz in order to dump a TGT from LSASS memory
- Pass the Ticket
  - Pass the ticket works by dumping the TGT from the LSASS memory of the machine
  - The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided
  - can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory
  - great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around
  - allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin
  - think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket
    ```
    sekurlsa::tickets /export - this will export all of the .kirbi tickets into the directory that you are currently in
    ```
  - we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges
  - ```
    kerberos::ptt <ticket> - run this command inside of mimikatz with the ticket that you harvested from earlier. It will cache and impersonate the given ticket
    ```
    ```
    klist - Here were just verifying that we successfully impersonated the ticket by listing our cached tickets
    ```
- Pass the Ticket Mitigation
  - Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.

# Golden/Silver Ticket Attacks w/ mimikatz
- A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket
- the approach to creating one is the exact same
- The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service
- A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server
- find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.
- KRBTGT Overview
  - A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients.
  - If you impersonate this account and create a golden ticket form the KRBTGT you give yourself the ability to create a service ticket for anything you want
  - A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.
- Golden/Silver Ticket Attack Overview
  -  attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket
  -  for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash
  -  use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information
- Dump the krbtgt hash
  - navigate to the directory mimikatz is in and run mimikatz
  - privilege::debug - ensure this outputs [privilege '20' ok]
  - lsadump::lsa /inject /name:krbtgt - This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account
- Create a Golden/Silver Ticket
```
  Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759d
b3f6 /id:500
```
- to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103
- misc::cmd - this will open a new elevated command prompt with the given ticket in mimikatz

# Kerberos Backdoors w/ mimikatz
- misc::skeleton - Yes! that's it but don't underestimate this small command it is very powerful
