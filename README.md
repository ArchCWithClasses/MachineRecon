# MachineRecon
This is a shell script to help with gaining initial foothold into a machine.

Siting nmapAutomator as source for idea on making automated reconnaissance script
https://github.com/21y4d/nmapAutomator

Siting hacktricks as resource for some nmap commands found in the script 
https://book.hacktricks.xyz/pentesting/pentesting-network

Author: ArchCWithClasses

Currently in beta testing phase and not being distributed. The machinerecon.sh script should be used for educational, ctf, or ethical hacking.

I have added the customWordlist.txt that I use for directory busting, to this repository. It is a combination of the /usr/share/seclists/Discovery/Web-Content/big.txt and /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt wordlists. I have removed duplicates from the list but you will have to change the location to fit your machine. 

Siting tools used by machinerecon.sh

nmap
https://github.com/nmap/nmap

smbmap
https://github.com/ShawnDEvans/smbmap

smbclient
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py

rpcclient
https://github.com/samba-team/samba/blob/master/source3/rpcclient/

ldapsearch
https://github.com/bindle/ldap-utils

dig
https://github.com/tigeli/bind-utils

smtp-user-enum
https://github.com/pentestmonkey/smtp-user-enum

snmp-check
http://www.nothink.org/codes/snmpcheck/

snmpwalk
https://github.com/net-snmp/net-snmp

droopescan
https://github.com/droope/droopescan

wpscan
https://github.com/wpscanteam/wpscan

joomscan
https://github.com/OWASP/joomscan

feroxbuster
https://github.com/epi052/feroxbuster

nikto
https://github.com/sullo/nikto
