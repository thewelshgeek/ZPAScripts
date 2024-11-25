#!/usr/bin/python3
import ldap, requests, json, datetime, base64, time, yaml, sys, os, getpass, srvlookup
from http import cookies

#Load Configuration
with open('config.yaml') as f:
    config = yaml.safe_load(f)

ZPAclientId=config['ZPAclientId']
ZPAclientSecret=config['ZPAclientSecret']
ZPACompanyID=config['ZPACompanyID']
ZPAEndpoint=config['ZPAEndpoint']

#Login to ZPA API Endpoitn
loginurl = ZPAEndpoint+"/signin"
logindata={"client_id":ZPAclientId,"client_secret":ZPAclientSecret}
auth=requests.post(loginurl,logindata).json()['access_token']
Headers={'Authorization':'Bearer '+auth,'Content-Type':'application/json'}

#SetEndpoints
CERTURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/certificate"
APURL = ZPAEndpoint+"/mgmtconfig/v1/admin/customers/"+ZPACompanyID+"/application"

#Get App To Update
app=json.loads(requests.get(APURL+'/72057606922831097', headers=Headers).text)

#Load Certifcate + Private Key
with open('newcert') as json_data:
	newcert=json.load(json_data)

#Update Certificate and get new ID
id=json.loads(requests.post(CERTURL, data=json.dumps(newcert), headers=Headers).text)['id']

#update App with new certificate
app['clientlessApps'][0]['certificateId']=id

#PUT data to update in cloud
r=requests.put(APURL+'/72057606922831097', data=json.dumps(app), headers=Headers)
