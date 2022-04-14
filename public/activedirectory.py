#!/usr/bin/python
import os
import requests
import json
import getpass
from http import cookies
import srvlookup

#Take input of Active Directoy Domain Suffix
#Connect to ZPA API.
#Perform DNS SRV lookup of All Active Directory Domain Controller
#Create App Segment for All Active Directory Domain Controllers, with appropriate ports

suffix = raw_input("Active Directory Domain Sufix:")

with open('config.yaml') as f:
    config = yaml.safe_load(f)

#Take input of ENI of Cloud Connector Service Interface
#Create Route53 Entries necessary to process ZPA Traffic

ZPAclientId=config['ZPAclientId']
ZPAclientSecret=config['ZPAclientSecret']
ZPACompanyID=config['ZPACompanyID']
ZPAEndpoint=config['ZPAEndpoint']

loginurl = ZPAEndpoint+"/signin"
logindata={"client_id":ZPAclientId,"client_secret":ZPAclientSecret}
auth=requests.post(loginurl,logindata).json()['access_token']
Headers={'Authorization':'Bearer '+auth,'Content-Type':'application/json'}

connectorGroupURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/appConnectorGroup"
serverGroupURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/serverGroup"
applicationGroupURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/segmentGroup"
applicationURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/application"
SAMLURL=ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/samlAttribute"
#Login to ZPA
auth=requests.post(loginurl,logindata).json()['access_token']

#Read Active Directory Servers.  Create string of all AD DC's FQDNs

srvrecord=srvlookup.lookup("ldap",protocol="tcp",domain=suffix)
fqdns=""
records=len(srvrecord)
for n in range(0, records):
	fqdns+="\""+srvrecord[n].hostname+"\""
	if n<records-1:
		fqdns+=","

#build Application Segment with TCP/UDP Ranges for Active Directory
tcpports="\"88\",\"88\",\"135\",\"135\",\"139\",\"139\",\"389\",\"389\",\"445\",\"445\",\"464\",\"464\",\"636\",\"636\",\"3268\",\"3269\",\"45000\",\"65535\""
udpports="\"88\",\"88\",\"389\",\"389\",\"137\",\"138\""

#read All Connector Groups.  Create a ServerGroup containing ALL connector Groups to link to Active Directory Application Segment
connectorGroups=requests.get(connectorGroupURL,headers=Headers).json()['list']
records=len(connectorGroups)
NewServerGroup="{\"enabled\":\"true\",\"name\":\"ActiveDirectoryServers\",\"learningEnabled\":\"true\",\"description\":\"Active Directory Servers Discovery\",\"assistantGroups\":[{"
for n in range(0, records):
	NewServerGroup+="\"id\":\""+connectorGroups[n]['id']+"\",\"name\":\""+connectorGroups[n]['name']+"\""
	if n<records-1:
		NewServerGroup+="},{"
	else:
		NewServerGroup+="}]}"

serverGroup=requests.post(serverGroupURL,NewServerGroup,headers=Headers).json()

#Build Appplication Segment Group and Application Segment
NewApplicationGroup="{\"enabled\":\"true\",\"name\":\"ActiveDirectoryServerGroup\",\"description\":\"Active Directory Servers Segment Group\",\"applications\":[]}"
ApplicationGroup=requests.post(applicationGroupURL,NewApplicationGroup,headers=Headers).json()

NewActiveDirectoryApplication="{\"applicationGroupId\": \""+ApplicationGroup['id']+"\",\"applicationGroupName\": \""+ApplicationGroup['name']+"\",\"bypassType\": \"NEVER\", \"cnameConfig\": \"NOFLATTEN\", \"configSpace\": \"DEFAULT\", \"description\": \"Active Directory Servers\", \"domainNames\": ["+fqdns+"],\"doubleEncrypt\":\"false\", \"enabled\": \"true\", \"healthCheckType\": \"DEFAULT\", \"healthReporting\": \"NONE\", \"name\": \"Active Directory Servers\", \"passiveHealthEnabled\": \"true\", \"serverGroups\": [{\"id\":\""+serverGroup['id']+"\"}], \"tcpPortRanges\": ["+tcpports+"],\"udpPortRanges\": ["+udpports+"]}"
Application=requests.post(applicationURL,NewActiveDirectoryApplication,headers=Headers).json()


