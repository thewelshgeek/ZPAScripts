import requests, json, yaml, re
import ldap, requests, json, datetime, base64, time, sys, re

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

with open('configbeta.yaml') as f:
    config = yaml.safe_load(f)

ZPAclientId=config['ZPAclientId']
ZPAclientSecret=config['ZPAclientSecret']
ZPACompanyID=config['ZPACompanyID']
ZPAEndpoint=config['ZPAEndpoint']
ZPAClientRegex=config['ZPAClientRegex']
ZPAClientDomain=config['ZPAClientDomain']

MobileClientId=config['MobileClientId']
MobileClientSecret=config['MobileClientSecret']
MobileCompanyId=config['MobileCompanyId']
MobileEndpoint=config['MobileEndpoint']



headers={"accept":"*/*","Content-Type":"application/json"}
payload={"apiKey":MobileClientId,"secretKey":MobileClientSecret}

login=requests.post(MobileEndpoint+"auth/v1/login",data=json.dumps(payload),headers=headers)
response=login.json()
headers['auth-token']=login.json()['jwtToken']
params={'companyId':MobileCompanyId}
devices=requests.get(MobileEndpoint+'public/v1/getDevices',headers=headers,params=params).json()
computerfqdns=''
for each in devices:
	if re.search(ZPAClientRegex,each['machineHostname']):
		if len(computerfqdns)==0:
			computerfqdns+='"'+each['machineHostname'].lower()+'.'+ZPAClientDomain.lower()+'"'
		else:
			computerfqdns+=',"'+each['machineHostname'].lower()+'.'+ZPAClientDomain.lower()+'"'


loginurl = ZPAEndpoint+"/signin"
logindata={"client_id":ZPAclientId,"client_secret":ZPAclientSecret}
auth=requests.post(loginurl,logindata).json()['access_token']
Headers={'Authorization':'Bearer '+auth,'Content-Type':'application/json'}

SegmentGroupURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/segmentGroup"
applicationURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/application"

if command=='Create' or command=='Update':
	#Build Application Segment with RDP and CIFS access for remote clients
	tcpportRanges='"445","445","3389","3389"'
	tcpportRange='{"from": "445", "to": "445"}, {"from": "3389", "to": "3389"}'
	udpports=''
	if command=='Create':
		#Build Appplication Segment Group
		NewSegmentGroup='{"enabled":"true","name":"Remote Clients","description":"Remote Clients","applications":[]}'
		SegmentGroup=requests.post(SegmentGroupURL,NewSegmentGroup,headers=Headers).json()
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

