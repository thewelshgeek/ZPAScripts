#!/usr/bin/python3
import ldap, json, yaml, sys, os, srvlookup, time

with open('config.yaml') as f:
    config = yaml.safe_load(f)

suffix=config['DomainSuffix']
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

#Construct JSON object of Active Directory Domain Controllers
Controllers={"list":[]}
n=0
for controller in srvrecord:
	Controllers["list"].append(controller.hostname)
	n=n+1

#Bind to LDAP
BindHostPort=srvrecord[0].hostname+':'+str(srvrecord[0].port)

l = ldap.initialize('ldap://'+BindHostPort)
bind=l.bind(BindUsername,BindPassword)
time.sleep(1)

#LDAP Search, return the AD Sites and their Subnets.  Put into JSON Object.
sites=l.search_s(SitesDN,ldap.SCOPE_SUBTREE,'(&(objectClass=site)(!(cn=Default-First-Site-Name)))',['cn','siteObjectBL'])
count=len(sites)
Locations={"list":[]}
for n in range(0, count):
	site=sites[n][1]['cn'][0].decode('utf-8')
	try:
		sncount=len(sites[n][1]['siteObjectBL'])
	except:
		sncount=0
	if sncount>0:
		sitedata={}
		sitedata["site"]=site
		sitedata["subnets"]=[]
		for m in range(0,sncount):
			sitedata["subnets"].append(sites[n][1]['siteObjectBL'][m].decode('utf-8').split(',')[0].split('=')[1])
		Locations["list"].append(sitedata)

print('Domain Controllers JSON')
print()
print(json.dumps(Controllers, indent=2))
print('AD Sites JSON')
print()
print(json.dumps(Locations, indent=2))

