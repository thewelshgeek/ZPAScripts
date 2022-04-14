#!/usr/bin/python3
import ldap, requests, json, datetime, base64, time, yaml, sys, re

#LDAP Connect to Directory
#Read from Computers DN all Computers.  Filter based on RegEx
#Create Application Segement and Segment Group in ZPA for Remote Access

with open('config.yaml') as f:
    config = yaml.safe_load(f)

#Read Computers matching expression
#Push to ZPA App Segment for Remote Control

BindHostPort=config['BindHostPort']
BindUsername=config['BindUsername']
BindPassword=config['BindPassword']
BindDN=config['BindDN']
TopGroupDN=config['TopGroupDN']
TopComputerDN=config['TopComputerDN']
ZPAclientId=config['ZPAclientId']
ZPAclientSecret=config['ZPAclientSecret']
ZPACompanyID=config['ZPACompanyID']
ZPAAPIEndpoint=config['ZPAAPIEndpoint']
ZPAClientRegex=config['ZPAClientRegex']

loginurl = ZPAAPIEndpoint+"/signin"
logindata={"client_id":ZPAclientId,"client_secret":ZPAclientSecret}
auth=requests.post(loginurl,logindata).json()['access_token']
Headers={'Authorization':'Bearer '+auth,'Content-Type':'application/json'}

SegmentGroupURL = ZPAAPIEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/segmentGroup"
applicationURL = ZPAAPIEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/application"

currentdatetime=datetime.datetime.utcnow()
ldaptime=currentdatetime.strftime('%Y%m%d%H%M%S.0Z')


argv=sys.argv[1:]
command=''
if argv==[]:
	print('computers.py [Create|Update|DeleteAll]')
	sys.exit()
for opt in argv:
  if opt in ("C", "Create"):
     command='Create'
  elif opt in ("U", "Update"):
     command = 'Update'
  elif opt in ("D", "Delete"):
     command = 'Delete'
  else:
     print('computers.py [Create|Update|Delete]')
     sys.exit()




if command=='Create' or command=='Update':
	l = ldap.initialize('ldap://'+BindHostPort)
	bind=l.bind(BindUsername,BindPassword)
	time.sleep(1)

	computers=l.search_s(TopComputerDN,ldap.SCOPE_SUBTREE,'(objectClass=computer)',['dNSHostName'])

	l.unbind()

	computerfqdns=''
	for each in computers:
		if 'dNSHostName' in each[1]:
			host=each[1]['dNSHostName'][0].decode('utf-8')
			if re.search(ZPAClientRegex,host):
				if len(computerfqdns)==0:
					computerfqdns+='"'+host+'"'
				else:
					computerfqdns+=',"'+host+'"'

	#Build Application Segment with RDP and CIFS access for remote clients
	tcpportRanges='"445","445","3389","3389"'
	tcpportRange='{"from": "445", "to": "445"}, {"from": "3389", "to": "3389"}'
	udpports=''
	if command=='Create':
		#Build Appplication Segment Group
		NewSegmentGroup='{"enabled":"true","name":"Remote Clients","description":"Remote Clients","applications":[]}'
		SegmentGroup=requests.post(SegmentGroupURL,NewSegmentGroup,headers=Headers).json()
		print(SegmentGroup)
		NewApplication='{"segmentGroupId": "'+SegmentGroup['id']+'","segementGroupName": "'+SegmentGroup['name']+'","bypassType": "NEVER", "cnameConfig": "NOFLATTEN", "configSpace": "DEFAULT", "description": "Remote Clients", "domainNames": ['+computerfqdns+'],"doubleEncrypt":"false", "enabled": "true", "healthCheckType": "DEFAULT", "healthReporting": "NONE", "name": "Remote Clients", "passiveHealthEnabled": "false", "serverGroups": [], "tcpPortRanges": ['+tcpportRanges+'], "tcpPortRange": ['+tcpportRange+'], "udpPortRanges": ['+udpports+']}'
		Application=requests.post(applicationURL,NewApplication,headers=Headers).json()

	if command=='Update':
		ApplicationsResponse=requests.get(applicationURL+'?search=Remote%20Clients',headers=Headers)
		Applications=json.loads(ApplicationsResponse.content)
		AppID=Applications['list'][0]['id']
		SegmentGroupID=Applications['list'][0]['segmentGroupId']
		SegmentGroupName=Applications['list'][0]['segmentGroupName']
		UpdatedApplication='{"segmentGroupId": "'+SegmentGroupID+'","segementGroupName": "'+SegmentGroupName+'","bypassType": "NEVER", "cnameConfig": "NOFLATTEN", "configSpace": "DEFAULT", "description": "Remote Clients", "domainNames": ['+computerfqdns+'],"doubleEncrypt":"false", "enabled": "true", "healthCheckType": "DEFAULT", "healthReporting": "NONE", "name": "Remote Clients", "passiveHealthEnabled": "false", "serverGroups": [], "tcpPortRanges": ['+tcpportRanges+'], "tcpPortRange": ['+tcpportRange+'], "udpPortRanges": ['+udpports+']}'
		Application=requests.put(applicationURL+'/'+AppID,UpdatedApplication,headers=Headers)


if command=='Delete':
	GroupResponse=requests.get(SegmentGroupURL+'?search=Remote%20Clients',headers=Headers)
	GroupID=GroupResponse.json()['list'][0]['id']
	ApplicationsResponse=requests.get(applicationURL+'?search=Remote%20Clients',headers=Headers)
	AppID=ApplicationsResponse.json()['list'][0]['id']
	Group=requests.delete(SegmentGroupURL+'/'+GroupID,headers=Headers)
	Application=requests.delete(applicationURL+'/'+AppID,headers=Headers)