#!/usr/bin/python

#Python3 Script - Takes input of a DNS Domain Name
#performs DNS SRV lookup for _ldap._tcp.domain.com
#which returns all Active Directory Domain Controllers
#in the directory.  Attempts CLDAP (UDP/389) Connection
#to each server and queries NetLogon service for details
#then outputs the result.  This enables a full view of 
#connectivity to domain controllers, and details of AD Site

#requires PIP
#curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
#python get-pip.py

#pip install pyasn1 --user
#pip install srvlookup --user

#References https://github.com/kimgr/asn1ate
#References https://github.com/etingof/pyasn1/ & http://snmplabs.com/pyasn1/
#References https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a


import socket,subprocess,os,pyasn1,ldap,srvlookup,sys
from struct import *
from pyasn1.type import univ, tag
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode

#Force Suppress errors to DevNull
class DevNull:
    def write(self, msg):
        pass

#sys.stderr = DevNull()

domaininput=sys.argv[1]

srvrecord=srvlookup.lookup("ldap",protocol="tcp",domain=domaininput)
print(srvrecord)
for srec in range(0, len(srvrecord)):
	testdc=srvrecord[srec].hostname
	testport=srvrecord[srec].port
	testip=srvrecord[srec].host

	ntver = "%c%c%c%c" % (6,0,0,0)
	cldap=ldap.LDAPMessage()
	cldap['messageID'] = 0
	search=ldap.SearchRequest()
	search['baseObject'] = ""
	search['scope'] = 0
	search['derefAliases'] = 0
	search['sizeLimit'] = 0
	search['timeLimit'] = 0
	search['typesOnly'] = 0
	filter1=ldap.Filter()
	filter1['equalityMatch']['attributeDesc']='DnsDomain'
	filter1['equalityMatch']['assertionValue']=domaininput
	filter2=ldap.Filter()
	filter2['equalityMatch']['attributeDesc'] = 'Host'
	filter2['equalityMatch']['assertionValue'] = testdc
	filter3=ldap.Filter()
	filter3['equalityMatch']['attributeDesc'] = 'NtVer'
	filter3['equalityMatch']['assertionValue'] = ntver
	filter4=ldap.Filter()
	filter4['and'].extend([filter1,filter2,filter3])
	attribute=ldap.AttributeDescription('Netlogon')
	attributes=ldap.AttributeDescriptionList()
	attributes.extend([attribute])
	search['attributes']=attributes
	search['filter']=filter4
	cldap['protocolOp']['searchRequest']=search
	substrate = encode(cldap)

	server=testip
	port=testport
	socket.setdefaulttimeout(2)
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.connect((server,port))
	sock.sendall(substrate)
	
	try:
		data=sock.recv(500)
	except:
		data="NR"
	sock.close()

	if data=="NR":
		print(testdc+" timed out")
	else:
#	Ignore first 2 Bytes - OpCode
#	Ignore next 4 Bytes - Flags
#	Ignore next 16 Bytes - Guid
#	Until 00 or 18 read into Domain - if 18 it = Forest
#	until 00 or 18 read into hostname - if 18 append forest to domain
#	until 00 read into NetBIOSDomain
#	unitl 00 read into NetBiOSHostname
#	Until 00 read into username
#	until 00 read into ServerSiteName
#	until 40 read into ClientSiteName
#	4 bytes Version Flags
#	8 bytes to end
		x=decode(data,asn1Spec=ldap.LDAPMessage())
		z=x[0]['protocolOp']['searchResEntry']['attributes'][0]['vals'][0]._value
		flag="forest"
		forest=""
		domain=""
		hostname=""
		NetBIOSDomain=""
		NetBIOSHostname=""
		username=""
		ServerSiteName=""
		ClientSiteName=""
		for i in range (25,len(z)-1):
			if flag=="forest":
				c=unpack_from('c',z,i)[0].decode('ascii')
				if c=="\x03":
					forest=forest+"."
				if c=="\x00":
					flag="domain"
				elif c!="c0" and c!="\x03":
					forest=forest+c
			elif flag=="domain":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')
				else:
					c="c0"
				if c=="\x00":
					flag="hostname"
				elif c=="\x18":
					flag="hostname"
					domain=forest
				elif c!="c0" and c!="\x03":
					domain=domain+c
			elif flag=="hostname":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')
				else:
					c="c0"
				if c=="\x00":
					flag="NetBIOSDomain"
				elif c=="\x18":
					flag="NetBIOSDomain"
					hostname=hostname+"."+domain
				elif c!="c0" and c!="\x03":
					hostname=hostname+c
			elif flag=="NetBIOSDomain":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')	
				if c=="\x00":
					flag="NetBIOSHostname"
				elif c!="c0" and c!="\x09":
					NetBIOSDomain=NetBIOSDomain+c
			elif flag=="NetBIOSHostname":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')	
				else:
					c="c0"	
				if c=="\x00":
					flag="username"
				elif c!="c0" and c!="\x03":
					NetBIOSHostname=NetBIOSHostname+c
			elif flag=="username":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')		
				if c=="\x00":
					flag="ServerSiteName"
					username=username+"<ROOT>"
				elif c!=b"\xc0":
					username=username+c
			elif flag=="ServerSiteName":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')
				else:
					c="c0"	
				if c=="\x00":
					flag="ClientSiteName"
				elif c!="c0" and c!="\x03" and c!="\x07":
					ServerSiteName=ServerSiteName+c
			elif flag=="ClientSiteName":
				c=unpack_from('c',z,i)[0]
				if c!=b"\xc0":
					c=c.decode('ascii')	
				else:
					c="c0"
					ClientSiteName=ServerSiteName
				if c=="\x00":
					flag="done"
				elif c!="c0" and c!="\x03" and c!="\x40"and c!="\x05":
					ClientSiteName=ClientSiteName+c
		srecord="DNS Server Record : IP="+srvrecord[srec].host+", PORT="+str(srvrecord[srec].port)+", PRIORITY="+str(srvrecord[srec].priority)+", WEIGHT="+str(srvrecord[srec].weight)+", HOSTNAME="+srvrecord[srec].hostname
		forest="AD Forest : "+forest
		domain="AD Domain : "+domain
		hostname="AD DC HostName : "+hostname
		NetBIOSDomain="AD NetBIOS Domain : "+NetBIOSDomain
		NetBIOSHostname="AD DC NetBIOS Name :"+NetBIOSHostname
		username="AD Username : "+username
		ServerSiteName="AD Server Site : "+ServerSiteName
		ClientSiteName="AD Client Site : "+ClientSiteName

		print(srecord)
		print(forest)
		print(domain)
		print(hostname)
		print(NetBIOSDomain)
		print(NetBIOSHostname)
		print(username)
		print(ServerSiteName)
		print(ClientSiteName)
