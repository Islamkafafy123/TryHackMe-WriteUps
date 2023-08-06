# Introuction
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
- To enumerate Kerberoastable accounts I would suggest a tool like BloodHound to find all Kerberoastable account
