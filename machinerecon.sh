#!/bin/bash

args=("$@")
currentDirectory=$(pwd)
 if [ "$EUID" -ne 0 ]
then 
    echo "Please run as root"
    exit
fi

if [ -z "${args[0]}" ]
then 
    echo "Enter IP"
    exit
fi


main() 
{
   # Define ANSI color variables
    RED='\033[1;31m'
    Green='\033[1;32m' 

    # Start script timer 
    start=$SECONDS
    ports=$(nmap -p- -T4 ${args[0]}| grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
    nmap -sCV -p$ports -T4 ${args[0]} -oN initial.txt &
    nmap -sUV --version-intensity 0 --max-retries 1 -T4 ${args[0]} -oN udpScan.txt &
    wait
    echo "$ports" >> openPorts.txt
    smb=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmicrosoft-ds/p" | wc -l)
    samba=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/Sambasmbd/p" | wc -l)
    rpc=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmsrpc/p" | wc -l)
    ldap=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openldap/p" | wc -l)
    dns=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/opendomain/p" | wc -l)
    smtp=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/opensmtp/p" | wc -l)
    snmp=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/opensnmp/p" | wc -l)
    httpPorts=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openhttp/p" | wc -l)
    httpsPorts=$(grep -i "ssl/http" initial.txt | wc -l)
    cms=$(grep http-generator initial.txt | cut -d " " -f 2)
    udpPorts=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/udpopen/p" | wc -l)
    
    udpFunc $udpPorts
    smbFunc $smb $samba
    ldapFunc $ldap
    rpcFunc $rpc $ldap
    dnsFunc $dns
    smtpFunc $smtp
    snmpFunc $snmp
    cmsFunc $cms
    wait
    httpFunc $httpPorts
    httpsFunc $httpsPorts
    wait
    echo -e ""
    echo -e ""
    echo -e "---------------------Finished Machine Recon------------------------"
    echo -e ""
    echo -e ""

            #End script timer
            end=$SECONDS
            duration=$(( end - start ))
            if [ ${duration} -gt 3600 ]; then
                    hours=$((duration / 3600))
                    minutes=$(((duration % 3600) / 60))
                    seconds=$(((duration % 3600) % 60))
                    printf "${RED}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
            elif [ ${duration} -gt 60 ]; then
                    minutes=$(((duration % 3600) / 60))
                    seconds=$(((duration % 3600) % 60))
                    printf "${Green}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
            else
                    printf "${RED}Completed in ${duration} seconds\n"
            fi
            echo -e ""
    exit 0

}

udpFunc()
{
    if [ $1 -gt 0 ];
    then
        udpOpenPorts=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/udpopen/p" | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
        nmap -sCVU -p$udpOpenPorts ${args[0]} -oN udpScriptScan.txt
    fi
}

smbFunc()
{
    if [ $1 -gt 0 ];
    then
        mkdir -p smbResults
        smbPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmicrosoft-ds/p" | cut -d "/" -f 1 | sed -n 1p)
        crackmapexec smb ${args[0]} -u '' -p '' --server-port $smbPort | tee "$currentDirectory/smbResults/WindowsOSVersion.txt" &
        crackmapexec smb ${args[0]} -u 'a' -p '' --server-port $smbPort --rid-brute | grep '(SidTypeUser)' | tee "$currentDirectory/smbResults/RidBruteUsersAnonymous.txt" &
        nmap -p$smbPort -sV --script vuln ${args[0]} -oN "$currentDirectory/smbResults/smbVuln.txt" &
        smbmap -u '' -p '' -R -H ${args[0]} -P $smbPort | tee "$currentDirectory/smbResults/smbMapAnonymous.txt" &
        smbclient -L ${args[0]} -p $smbPort -N | tee "$currentDirectory/smbResults/smbClient.txt"
        shares=$(cat smbResults/smbClient.txt | sed -n "/Disk/p" | wc -l)
        for (( k=0; k<$shares; k++ ))   
        do 
            shareLine=$((k+1))
            shareName=$(cat smbResults/smbClient.txt | sed -n "/Disk/p" | sed -n $(echo $shareLine)p | sed 's/Disk.*//g' | sed 's/^[ \t]*//;s/[ \t]*$//')
            smbclient //${args[0]}/$shareName -p $smbPort -c dir -N | tee "$currentDirectory/smbResults/DirectoryListing$shareName.txt"
            smbAccess=$(cat "$currentDirectory/smbResults/DirectoryListing$shareName.txt" | sed 's/^[ \t]*//;s/[ \t]*$//')
            if [[ ! $smbAccess =~ "NT_STATUS_ACCESS_DENIED" ]];
            then
                mkdir -p "$currentDirectory/smbResults/$shareName"
                smbclient //${args[0]}/$shareName -p $smbPort -N -Tc "$currentDirectory/smbResults/$shareName/$shareName.tar";tar xf "$currentDirectory/smbResults/$shareName/$shareName.tar" -C "$currentDirectory/smbResults/$shareName"
            fi
        done

    elif [ $2 -gt 0 ]; 
    then
        mkdir -p sambaResults
        sambaPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/Sambasmbd/p" | cut -d "/" -f 1 | sed -n 1p)
        timeout 5 ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' port $sambaPort | tee "$currentDirectory/sambaResults/sambaVersion.txt" &
        smbclient -L ${args[0]} -p $sambaPort -N | tee "$currentDirectory/sambaResults/smbClient.txt"
        sleep 5
        nmap -sV --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version ${args[0]} -p$sambaPort -oN "$currentDirectory/sambaResults/sambaVuln.txt" &
        smbmap -u '' -p '' -R -H ${args[0]} -P $sambaPort | tee "$currentDirectory/sambaResults/smbMapAnonymous.txt" &
        shares=$(cat sambaResults/smbClient.txt | sed -n "/Disk/p" | wc -l)
        for (( l=0; l<$shares; l++ ))   
        do 
            shareLine=$((l+1))
            shareName=$(cat sambaResults/smbClient.txt | sed -n "/Disk/p" | sed -n $(echo $shareLine)p | sed 's/Disk.*//g' | sed 's/^[ \t]*//;s/[ \t]*$//')
            smbclient //${args[0]}/$shareName -p $sambaPort -c dir -N | tee "$currentDirectory/sambaResults/DirectoryListing$shareName.txt"
            sambAccess=$(cat "$currentDirectory/sambaResults/DirectoryListing$shareName.txt" | sed 's/^[ \t]*//;s/[ \t]*$//')
            if [[ ! $sambAccess =~ "NT_STATUS_ACCESS_DENIED" ]];
            then
                mkdir -p "$currentDirectory/sambaResults/$shareName"
                smbclient //${args[0]}/$shareName -p $sambaPort -N -Tc "$currentDirectory/sambaResults/$shareName/$shareName.tar";tar xf "$currentDirectory/sambaResults/$shareName/$shareName.tar" -C "$currentDirectory/sambaResults/$shareName"
            fi

        done
    fi

}

ldapFunc()
{
    if [ $1 -gt 0 ];
    then
        ldapPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openldap/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p ldapResults
        ldapsearch -x -h ${args[0]} -s base namingcontexts -p$ldapPort | tee "$currentDirectory/ldapResults/ldapNamingContexts.txt"
        namingContext=$(cat ldapNamingContexts.txt | sed -n "/namingcontexts:/Ip" | cut -d "/" -f 1 | sed -n 1p | sed 's/[^ ]* //')
        ldapsearch -x -h ${args[0]} -b "$namingContext" | tee "$currentDirectory/ldapResults/ldapSearchInfo.txt" &
        nmap -sV --script "ldap* and not brute" ${args[0]} -p$ldapPort -oN "$currentDirectory/ldapResults/ldapEnumerationScript.txt" &
    fi
}

rpcFunc()
{
    if [ $1 -gt 0 ];
    then
        rpcPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openmsrpc/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p rpcResults
        rpcclient -U "" -N ${args[0]} -c enumdomusers --port -p$rpcPort | tee "$currentDirectory/rpcResults/enumDomUsers.txt"
        rpcAccess=$(sed -n 1p rpcResults/enumDomUsers.txt | sed 's/.* //')
        if [[ $rpcAccess != "NT_STATUS_ACCESS_DENIED" ]];
        then 
            cat rpcResults/enumDomUsers.txt | awk -F\[ '{print $2}' | awk -F\] '{print $1}' | tee "$currentDirectory/rpcResults/domainUsers.txt" &
            if [$2 -gt 0];
            then
                domainName=$(cat "$currentDirectory/ldapResults/ldapNamingContexts.txt" | sed -n "/namingcontexts:/p" | cut -d "/" -f 1 | sed -n 1p | sed 's/[^ ]* //' | sed 's/DC=//g' | sed 's/,/./g')
                GetNPUsers.py $domainName/ -usersfile "$currentDirectory/rpcResults/domainUsers.txt" -dc-ip ${args[0]} -format hashcat -outputfile "$currentDirectory/rpcResults/asRepHashes.txt"
            fi
        fi    
    fi
}

dnsFunc()
{
    if [ $1 -gt 0 ];
    then
        dnsPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/opendomain/p" | cut -d "/" -f 1 | sed -n 1p) 
        mkdir -p dnsResults
        dig -x ${args[0]} @${args[0]} +nocookie -p $dnsPort | tee "$currentDirectory/dnsResults/digOutput.txt" &
    fi
}

smtpFunc()
{
    if [ $1 -gt 0 ];
    then 
        smtpPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/opensmtp/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p smtpResults
        smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t ${args[0]} -p $smtpPort | tee "$currentDirectory/smtpResults/smptUserEnumSecList.txt" &
    fi
}

snmpFunc()
{
    if [ $1 -gt 0 ];
    then
        snmpPort=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/opensnmp/p" | cut -d "/" -f 1 | sed -n 1p)
        mkdir -p snmpResults
        snmp-check -c public ${args[0]}:$snmpPort | tee "$currentDirectory/snmpResults/snmpCheck.txt" &
        snmpwalk -Os -c public -v1 ${args[0]}:$snmpPort | tee "$currentDirectory/snmpResults/snmpWalk.txt" &
    fi
}


cmsFunc()
{
    if [[ $1 =~ "Drupal" ]]; 
    then 
        mkdir -p drupalResults
        drupalPort=$(grep -i Drupal initial.txt --before-context=1 | sed -n 1p | cut -d '/' -f 1)
        droopescan scan drupal -u http://${args[0]}:$drupalPort/ | tee "$currentDirectory/drupalResults/drupalScan.txt" &

    elif [[ $1 =~ "WordPress" ]];
    then
        mkdir -p wordPressResults
        wordPressPort=$(grep -i WordPress initial.txt --before-context=1 | sed -n 1p | cut -d '/' -f 1)
        if [ $wordPressPort -eq 443 ];
        then
            wpscan --url https://$wordPressPort/ -e vp,vt,tt,u,cb,dbe -t 50 --api-token  z49lXGZjStpnfIbFOPHF0d3ceSD5kufNo5kVpGfHyhk --update -o "$currentDirectory/wordPressResults/wpscanHTTPS.txt" &
        else 
            wpscan --url http://${args[0]}:$wordPressPort/ -e vp,vt,tt,u,cb,dbe -t 50 --api-token  z49lXGZjStpnfIbFOPHF0d3ceSD5kufNo5kVpGfHyhk --update -o "$currentDirectory/wordPressResults/wpscanHTTP.txt" &
        fi
        nmap ${args[0]} -p$wordPressPort --script http-wordpress* -oN "$currentDirectory/wordPressResults/nmapWordPress.txt" &

    elif [[ $1 =~ "Joomla" ]]; 
    then
        mkdir -p joomlaResults
        joomlaPort=$(grep -i Joomla initial.txt --before-context=1 | sed -n 1p | cut -d '/' -f 1)
        joomscan --url http://${args[0]}:$joomlaPort/ --enumerate-components | tee "$currentDirectory/joomlaResults/joomlaScan.txt" &
    elif [[ $1 =~ "Silverstripe" ]]; 
    then
        mkdir -p silverStripeResults
        silverStripePort=$(grep -i Silverstripe initial.txt --before-context=1 | sed -n 1p | cut -d '/' -f 1)
        droopescan scan silverstripe -u http://${args[0]}:$silverStripePort/ | tee "$currentDirectory/silverStripeResults/silverStripeScan.txt" &
    fi
}


httpFunc()
{
    
    if [ $1 -gt 0 ];
    then
        mkdir -p httpResults
        for (( i=0; i<$1; i++ ))   
        do 
            httpLine=$((i+1))
            httpPort=$(cat initial.txt | sed -r 's/\s+//g' | sed -n "/openhttp/p" | cut -d "/" -f 1 | sed -n $(echo $httpLine)p)
            microsoftHTTPAPI=$(grep -i $httpPort/tcp initial.txt | sed -n "/Microsoft HTTPAPI/p" | wc -l)
            if [[ $microsoftHTTPAPI -eq 0 ]];
            then
                feroxbuster -u http://${args[0]}:$httpPort/ -w /home/kali/Desktop/test/customWordlist.txt -d 2 -k -x html,php,txt,jsp -s 200,301,302 -o "$currentDirectory/httpResults/feroxbusterRecursion$httpPort.txt" &
                nikto -host ${args[0]}:$httpPort -ask=no -maxtime 900 | tee "$currentDirectory/httpResults/nikto$httpPort.txt" &
            fi
        done
    fi
}

httpsFunc()
{

    if [ $1 -gt 0 ];
    then
        mkdir -p httpsResults
        for (( j=0; j<$1; j++ ))   
        do 
            httpsLine=$((j+1))
            httpsPort=$(grep -i "ssl/http" initial.txt | cut -d "/" -f 1 | sed -n $(echo $httpsLine)p)
            microsoftHttpsHTTPAPI=$(grep -i $httpsPort/tcp initial.txt | sed -n "/Microsoft HTTPAPI/p" | wc -l)
            if [[ $microsoftHttpsHTTPAPI -eq 0 ]];
            then
                feroxbuster -u https://${args[0]}:$httpsPort/ -w /home/kali/Desktop/test/customWordlist.txt -d 2 -x html,php,txt,jsp -s 200,301,302 -o "$currentDirectory/httpsResults/feroxbusterRecursion$httpsPort.txt" &
                nikto -host ${args[0]}:$httpsPort -ask=no -ssl -maxtime 900 | tee "$currentDirectory/httpsResults/nikto$httpsPort.txt" &
            fi
        done
    fi
}

main
