#!/usr/bin/python3
import ldap, requests, json, datetime, base64, time, yaml, sys, os, getpass, srvlookup
from http import cookies


with open('config.yaml') as f:
    config = yaml.safe_load(f)

suffix=config['DomainSuffix']
ZPAclientId=config['ZPAclientId']
ZPAclientSecret=config['ZPAclientSecret']
ZPACompanyID=config['ZPACompanyID']
ZPAEndpoint=config['ZPAEndpoint']
BindUsername=config['BindUsername']
BindPassword=config['BindPassword']

splitsuffix=suffix.split('.')
count=len(splitsuffix)

#Build the DNs - Base, Sites and DNS Domain
DN=""
for n in range(0, count):
	DN+='DC='+splitsuffix[n]
	if n<count-1:
		DN+=","

SitesDN='cn=sites,cn=configuration,'+DN
DNSDN='DC='+suffix+',CN=MicrosoftDNS,DC=DomainDnsZones,'+DN

#Perform DNS SRV Lookup.  Return an Active Directory Domain Controller, capable of taking LDAP Bind.
srvrecord=srvlookup.lookup("ldap",protocol="tcp",domain=suffix)

#Bind to LDAP
BindHostPort=srvrecord[0].hostname+':'+str(srvrecord[0].port)

l = ldap.initialize('ldap://'+BindHostPort)
bind=l.bind(BindUsername,BindPassword)
time.sleep(1)

#LDAP Search, return the AD Sites and their Subnets.  Put into JSON Object.
sites=l.search_s(SitesDN,ldap.SCOPE_SUBTREE,'(&(objectClass=site)(!(cn=Default-First-Site-Name)))',['cn','siteObjectBL'])
count=len(sites)
Locations={}
for n in range(0, count):
	site=sites[n][1]['cn'][0].decode('utf-8')
	try:
		sncount=len(sites[n][1]['siteObjectBL'])
	except:
		sncount=0
	if sncount>0:
		Locations[n]={}
		Locations[n]['site']=site
		Locations[n]['subnets']={}
		for m in range(0,sncount):
			Locations[n]['subnets'][m]=sites[n][1]['siteObjectBL'][m].decode('utf-8').split(',')[0].split('=')[1]

print(Locations)
#We can now create / output the AD Sites for Zscaler App Connector creation.
#App Connector should be called "Site" - and be in the "Subnet"
#Create Provisioning Key "Active Directory - Suffix"
#Create App Connector Group "Site" using Provision Key
#Create ServerGroup "Active Directory" containing all "App Connector Groups"

loginurl = ZPAEndpoint+"/signin"
logindata={"client_id":ZPAclientId,"client_secret":ZPAclientSecret}
auth=requests.post(loginurl,logindata).json()['access_token']
Headers={'Authorization':'Bearer '+auth,'Content-Type':'application/json'}

CGURL=ZPAEndpoint+'/mgmtconfig/v1/admin/customers/'+ZPACompanyID+'/appConnectorGroup'
PKURL=ZPAEndpoint+'/mgmtconfig/v1/admin/customers/'+ZPACompanyID+'/associationType/CONNECTOR_GRP/provisioningKey'
ECURL=ZPAEndpoint+'/mgmtconfig/v2/admin/customers/'+ZPACompanyID+'/enrollmentCert?page=&pagesize=&search=connector'
SGURL=ZPAEndpoint+'/mgmtconfig/v1/admin/customers/'+ZPACompanyID+'/serverGroup'
AGURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/segmentGroup"
APURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/application"

#Retrieve Enrollment certificate ID - MUST find one called "connector" - will use first one it finds
enrollmentcertId=json.loads(requests.get(ECURL, headers=Headers).content.decode('utf-8'))['list'][0]['id']


#Create the App Connector Groups
ADCgroups=[]
count=len(Locations)
for n in range(0, count):	
	#We don't know the locations - put them all at 0,0 - customer can update manually based on their data
	#Create ConnectorGroup for each Active Directory Site
	ConnectorGroupPostData={
	  "description": 'ActiveDirectorySite-'+Locations[n]['site'],
	  "dnsQueryType": "IPV4_IPV6",
	  "enabled": "true",
	  "latitude": '0.0',
	  "location": 'London,UK',
	  "longitude": '0.0',
	  "name": 'ActiveDirectorySite-'+Locations[n]['site'],
	  "overrideVersionProfile": "true",
	  "lssAppConnectorGroup": "false",
	  "upgradeDay": "SUNDAY",
	  "upgradeTimeInSecs": "82800",
	  "versionProfileId": "0"
	}
	#Create Connector Group
	ConnectorGroupID=json.loads(requests.post(CGURL, data=json.dumps(ConnectorGroupPostData).encode('utf-8'), headers=Headers).content.decode('utf-8'))["id"]
	#Generate Provisioning Key POST data
	ProvisioningKeyPostData={
	  "appConnectorGroupId": ConnectorGroupID,
	  "enabled": "true",
	  "maxUsage": 1000,
	  "name": 'ActiveDirectorySite-'+Locations[0]['site'],
	  "enrollmentCertId": enrollmentcertId
	}
	ProvisioningKey=json.loads(requests.post(PKURL, data=json.dumps(ProvisioningKeyPostData).encode('utf-8'), headers=Headers).content.decode('utf-8'))
	ADCgroups.append({"id":ConnectorGroupID})

#Create a Server Group containing all the Active Directory App Connectors
ServerGroupPostData={
  "appConnectorGroups":ADCgroups,
  "configSpace": "DEFAULT",
  "description": "ActiveDirectorySites",
  "enabled": "true",
  "dynamicDiscovery": "true",
  "name": "ActiveDirectorySites"
}
ServerGroup=json.loads(requests.post(SGURL, data=json.dumps(ServerGroupPostData).encode('utf-8'), headers=Headers).content.decode('utf-8'))

#Build Segment with all Domain Controllers returned from DNS SRV Lookup
fqdns=[]
records=len(srvrecord)
for n in range(0, records):
	fqdns.append(srvrecord[n].hostname)

#build Application Segment with TCP/UDP Ranges for Active Directory
tcpports=["88","88","135","135","139","139","389","389","445","445","464","464","636","636","3268","3269","45000","65535"]
udpports=["88","88","389","389","137","138"]

#Build Appplication Segment Group and Application Segment
NewApplicationGroup={
 "enabled":"true",
 "name":"ActiveDirectoryServerGroup",
 "description":"Active Directory Servers Segment Group",
 "applications":[]
 }
ApplicationGroup=requests.post(AGURL,data=json.dumps(NewApplicationGroup).encode('utf-8'),headers=Headers).json()
NewActiveDirectoryApplication={
 "applicationGroupId": ApplicationGroup['id'],
 "applicationGroupName": ApplicationGroup['name'],
 "bypassType": "NEVER",
 "cnameConfig": "NOFLATTEN",
 "configSpace": "DEFAULT",
 "description": "Active Directory Servers",
 "domainNames": fqdns,
 "doubleEncrypt":"false",
 "enabled": "true",
 "healthCheckType": "DEFAULT",
 "healthReporting": "NONE",
 "name": "Active Directory Servers",
 "passiveHealthEnabled": "true",
 "serverGroups": [{"id":ServerGroup['id']}],
 "tcpPortRanges": tcpports,
 "udpPortRanges": udpports
 }
Application=requests.post(APURL,data=json.dumps(NewActiveDirectoryApplication).encode('utf-8'),headers=Headers).json()

#Now - LDAP Query for all other computer objects.  Create Segments for each FQDN.
#RecordType 1 is A Record, 5 is CNAME
create=[]
servers=l.search_ext_s(DNSDN,ldap.SCOPE_SUBTREE,'(&(objectClass=dnsNode)(!(dnsTombstoned=TRUE)))',['dc','dnsRecord'],sizelimit=0)
noservers=len(servers)
for n in range(0,noservers):
	try:
		recordtype=servers[n][1]['dnsRecord'][0][2]
		if recordtype==1 or recordtype==5:
			fqdn=servers[n][1]['dc'][0].decode('utf-8')+'.'+suffix
			create.append(fqdn)
	except:
		recordtype=servers[n]


NewApplicationGroup={
 "enabled":"true",
 "name":"AUTOCREATEDNS",
 "description":"AUTOCREATEDNS",
 "applications":[]
 }
ApplicationGroup=requests.post(AGURL,data=json.dumps(NewApplicationGroup).encode('utf-8'),headers=Headers).json()
tcpports=["1","65535"]
udpports=["1","65535"]
NewActiveDirectoryApplication={
 "applicationGroupId": ApplicationGroup['id'],
 "applicationGroupName": ApplicationGroup['name'],
 "bypassType": "NEVER",
 "cnameConfig": "NOFLATTEN",
 "configSpace": "DEFAULT", 
 "description": "AUTOCREATEDNS",
 "domainNames": create,
 "doubleEncrypt":"false",
 "enabled": "true",
 "healthCheckType": "DEFAULT",
 "healthReporting": "NONE",
 "name": "AUTOCREATEDNS",
 "passiveHealthEnabled": "true",
 "serverGroups": [{"id":ServerGroup['id']}],
  "tcpPortRanges": tcpports,
  "udpPortRanges": udpports
  }
Application=requests.post(APURL,data=json.dumps(NewActiveDirectoryApplication).encode('utf-8'),headers=Headers).json()
