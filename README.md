# MachineRecon
This is a shell script to help with gaining initial foothold into a machine.

#siting nmapAutomator as source for idea on making automated reconnaissance script
https://github.com/21y4d/nmapAutomator

#siting hacktricks as resource for some nmap commands found in the script 
https://book.hacktricks.xyz/

#Author: ArchCWithClasses
#Currently in beta testing phase and not being distributed. The machinerecon.sh script should be used for educational, ctf, or ethical hacking.

#Tools used by machinerecon.sh 
nmap, smbmap, smbclient, rpcclient, ldapsearch, dig, smtp-user-enum, snmp-check, snmpwalk, droopescan, wpscan, joomscan, feroxbuster, and nikto

#Steps to run machinerecon.sh 
make MachineRecon directory 
mkdir -p MachineRecon
place machinerecon.sh into the directory 
chmod 777 or chmod +x machinerecon.sh 
Create symbolic link for machinerecon.sh in /usr/local/bin/
sudo ln -s $(pwd)/MachineRecon/machinerecon.sh /usr/local/bin/
run machinerecon.sh as root and give script intended ip as parameter. Make sure that you are able to ping the ip, the script doesn't support -Pn(doesn't do host discovery) for nmap scans. 
sudo machinerecon.sh IP
 
#Install ldapsearch on Kali
sudo apt-get install ldap-utils

#Install dig on Kali 
sudo  apt install dnsutils

#Install smtp-user-enum on Kali 
sudo apt-get install smtp-user-enum

#Install snmp-check on Kali 
sudo apt-get install snmpcheck

#Install snmpwalk on Kali 
sudo apt-get install snmp

#Install droopescan on Kali 
First make sure that pip is intalled 
sudo apt install python3-pip
Then install droopescan with pip
sudo pip install droopescan 

#Install joomscan on Kali 
sudo apt-get install joomscan

#Steps to install feroxbuster 
make FeroxBuster directory
mkdir -p FeroxBuster
download x86_64-linux-feroxbuster.tar.gz into directroy
wget https://github.com/epi052/feroxbuster/releases/download/v2.3.0/x86_64-linux-feroxbuster.tar.gz
Extract tar.gz file into the folder 
tar -xf x86_64-linux-feroxbuster.tar.gz
chmod 777 or chmod +x feroxbuster elf binary 
Create symbolic link for feroxbuster elf binary in /usr/local/bin/
sudo ln -s $(pwd)/FeroxBuster/feroxbuster /usr/local/bin/
Type feroxbuster into terminal and usage options should appear
