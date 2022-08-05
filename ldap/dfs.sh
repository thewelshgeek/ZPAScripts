#!/bin/bash
#Script creates Kerberos configuration on CentOs server (App Connector) and installs Samba/CIFS clinet
#Enumerates Active Directory Domain Controllers
#Connects to AD DFS Mountpoint for GPO across all resolvable servers (A Record for domain) - Authenticated via NTLM
#Connects to AD Servers directly (SRV Record for _ldap._tcp.domain.com) - Authenticated via Kerberos

#yum install krb5-libs, krb5-workstation, samba-client samba-common cifs-utils -y
read -p "Username: " username
echo -n Password: 
read -s password
echo
read -p "Domain: " domain
kdestroy -A

cat > ./krb5.conf << "END_OF_SCRIPT"
[libdefaults]
 default_realm = domainu
 forwardable = true
 proxiable = true
 allow_weak_crypto = true
 dns_lookup_kdc = true
 dns_lookup_realm = true

[realms]
 domainu = {
  default_domain = domainl
}

[domain_realm]
 .domainl=domainu
 domainl=domainu

[logging]
  kdc = FILE:/var/log/kdc.log
  admin_server = FILE:/var/log/kadmin.log
  default = FILE:/var/log/krb5lib.log
END_OF_SCRIPT

sed -i 's/domainu/'"${domain^^}"'/g' krb5.conf
sed -i 's/domainl/'"${domain,,}"'/g' krb5.conf

echo Receiving Kerberos TGT
echo ${password} | kinit ${username,,} 2> /dev/null
echo Received Kerberos Ticket
klist | grep krbtgt
echo

echo Starting DFS Mount of Sysvol shares
echo

mkdir -p /mnt/smb
for eachIP in $(dig ${domain} +short)
do
   echo Connecting to ${domain}\\SYSVOL at IP ${eachIP} using NTLM
   mount //${domain}/sysvol /mnt/smb -osec=ntlmv2,domain=${domain},username=${username},password=${password},ip=${eachIP} 2> /dev/null
   files=`ls -l /mnt/smb`
   if [[ "$files" == "total 0" ]]; then
   	 echo Failed to mount ${domain}\\SYSVOL at IP ${eachIP} using NTLM
   else
   	 echo Mounted ${domain}\\SYSVOL at IP ${eachIP} .  Contents of ${domain} directory
   	 ls /mnt/smb/${domain}
   fi
   umount /mnt/smb 2> /dev/null
done

echo Finished DFS Mounts
echo 
echo Starting Server Mounts of Sysvol Shares
echo

servers=`dig SRV _ldap._tcp.${domain} +short | cut -f 4 -d ' '`
echo SRV Lookup for _ldap._tcp.${domain} returns $servers

for eachHost in ${servers}
do
   host=${eachHost::-1}
   echo Connecting to ${host}\\SYSVOL using Kerberos
   mount //$host/sysvol /mnt/smb -osec=krb5 2> /dev/null
   files=`ls -l /mnt/smb`
   if [[ "$files" == "total 0" ]]; then
   	 echo Failed to mount ${host}\\SYSVOL using Kerberos
   else
   	 echo Mounted ${host}\\SYSVOL .  Contents of ${domain} directory
   	 ls /mnt/smb/${domain}
   fi
   umount /mnt/smb 2> /dev/null
done

#Cleanup mount points and Kerberos tickets
rmdir  /mnt/smb
kdestroy -A