#!/usr/bin/python
import subprocess
import json
import os
import requests
import getpass
import yaml
from http import cookies

#Takes input of domain Suffix to form FQDN of a server, and PCAP of client logging into SAP
#Passes the PCAP through TSHARK which has SAP disector loaded
#Outputs a JSON File containing the SAP Disections
#Parses the SAP Disection JSON to create Application Segments
#Pushes the SAP Application Segments to ZPA

suffix = raw_input("Domain Suffix of SAP Servers:")
file = raw_input("SAP PCAP FileName:")
os.system('tshark -r '+file+' -E occurrence=a -T json -e "sapms.serverlst.name" -e "sapms.serverlst.host" -e "sapms.serverlst.status" -e "sapms.serverlst.hostaddr4" -e "sapms.serverlst.servno" "sapms.serverlst.name" > ./sapfile.json 2>/dev/null')


with open('config.yaml') as f:
    config = yaml.safe_load(f)


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

with open("./sapfile.json") as sapfile:
	saplist=json.load(sapfile)

appsegs=set()
ports=set()

for a in range(len(saplist)):
	objects=len(saplist[a][str('_source')][str('layers')][str('sapms.serverlst.status')])
	for n in range(objects):
		if str(saplist[0][str('_source')][str('layers')][str('sapms.serverlst.status')][n])=="0x00000001":
			hostline="\""+str(saplist[0][str('_source')][str('layers')][str('sapms.serverlst.host')][n].rstrip())+"."+suffix+"\""
			ipline="\""+str(saplist[0][str('_source')][str('layers')][str('sapms.serverlst.hostaddr4')][n])+"\""
			portline="\""+str(saplist[0][str('_source')][str('layers')][str('sapms.serverlst.servno')][n])+"\""
			if hostline not in appsegs:
				appsegs.add(hostline)
				print(hostline)
			if ipline not in appsegs:
				appsegs.add(ipline)
				print(ipline)
			if portline not in ports:
				ports.add(portline)
				print(portline)

fqdns=""
for n in range(0, len(appsegs)):
	fqdns+=list(appsegs)[n]
	if n<len(appsegs)-1:
		fqdns+=","

tcpports=""
for n in range(0, len(ports)):
	tcpports+=list(ports)[n]+","+list(ports)[n]
	if n<len(ports)-1:
		tcpports+=","

#read All Connector Groups.  Create a ServerGroup containing ALL connector Groups to link to Active Directory Application Segment
connectorGroups=requests.get(connectorGroupURL,headers=Headers).json()['list']
records=len(connectorGroups)
NewServerGroup="{\"enabled\":\"true\",\"name\":\"SAP Servers\",\"learningEnabled\":\"true\",\"description\":\"SAP Servers\",\"assistantGroups\":[{"
for n in range(0, records):
	NewServerGroup+="\"id\":\""+connectorGroups[n]['id']+"\",\"name\":\""+connectorGroups[n]['name']+"\""
	if n<records-1:
		NewServerGroup+="},{"
	else:
		NewServerGroup+="}]}"

serverGroup=requests.post(serverGroupURL,NewServerGroup,headers=Headers).json()

#Build Appplication Segment Group and Application Segment
NewApplicationGroup="{\"enabled\":\"true\",\"name\":\"SAP Servers\",\"description\":\"SAP Servers Segment Group\",\"applications\":[]}"
ApplicationGroup=requests.post(applicationGroupURL,NewApplicationGroup,headers=Headers).json()

NewActiveDirectoryApplication="{\"applicationGroupId\": \""+ApplicationGroup['id']+"\",\"applicationGroupName\": \""+ApplicationGroup['name']+"\",\"bypassType\": \"NEVER\", \"cnameConfig\": \"NOFLATTEN\", \"configSpace\": \"DEFAULT\", \"description\": \"SAP Servers\", \"domainNames\": ["+fqdns+"],\"doubleEncrypt\":\"false\", \"enabled\": \"true\", \"healthCheckType\": \"DEFAULT\", \"healthReporting\": \"NONE\", \"name\": \"SAP Servers\", \"passiveHealthEnabled\": \"true\", \"serverGroups\": [{\"id\":\""+serverGroup['id']+"\"}], \"tcpPortRanges\": ["+tcpports+"]}"
Application=requests.post(applicationURL,NewActiveDirectoryApplication,headers=Headers).json()

