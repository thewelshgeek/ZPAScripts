#!/usr/bin/python3
#https://assets.falcon.crowdstrike.com/support/api/swagger.html
import jwt, requests, json, datetime, base64, time, yaml, sys, os, pprint

#Read config file, connect to Crowdstrike API
with open('config.yaml') as f:
    config = yaml.safe_load(f)

CSclientId=config['CSclientId']
CSclientSecret=config['CSclientSecret']
CSCompanyID=config['CSCompanyID']
CSEndpoint=config['CSEndpoint']
payload={"client_id":CSclientId,"client_secret":CSclientSecret}
authurl=CSEndpoint+"/oauth2/token"
bearer=json.loads(requests.post(authurl,data=payload).text)['access_token']
headers={'authorization':'bearer '+bearer}


#Open Crowdsrike JWT File Locally
with open('/Library/Application Support/CrowdStrike/ZeroTrustAssessment/data.zta') as f:
    encoded_jwt = f.read()

#Download Crowdtrike JWKS File    
jwks=json.loads(requests.get('https://assets-public.falcon.crowdstrike.com/zta/jwk.json').text)

#Extract Public Keys from JWKS File for verification
public_keys = {}
for jwk in jwks['keys']:
    kid = jwk['kid']
    public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

kid = jwt.get_unverified_header(encoded_jwt)['kid']
key = public_keys[kid]

#Decode JWT, Verifying against JWKS
decoded_jwt = jwt.decode(encoded_jwt, key=key, algorithms=['RS256'])

#Take Device ID from Local JWT.  Connect to Crowdstrike API and download Device Details
deviceurl=CSEndpoint+'/devices/entities/devices/v1'
params='ids='+decoded_jwt['sub']
deviceinfo=json.loads(requests.get(deviceurl,headers=headers,params=params).text)['resources'][0]

print("DeviceInfo")
pprint.pprint(deviceinfo)
print()
ppid=deviceinfo['device_policies']['prevention']['policy_id']
spid=deviceinfo['device_policies']['sensor_update']['policy_id']
dcid=deviceinfo['device_policies']['device_control']['policy_id']

ppurl=CSEndpoint+'/policy/entities/prevention/v1'
params='ids='+ppid
pp=json.loads(requests.get(ppurl,headers=headers,params=params).text)['resources'][0]
print("Prevention Policy")
pprint.pprint(pp)
print()
spurl=CSEndpoint+'/policy/entities/sensor-update/v1'
params='ids='+spid
sp=json.loads(requests.get(spurl,headers=headers,params=params).text)['resources'][0]
print("SensorPolicy")
pprint.pprint(sp)
print()
dcurl=CSEndpoint+'/policy/entities/device-control/v1'
params='ids='+dcid
dc=json.loads(requests.get(dcurl,headers=headers,params=params).text)['resources'][0]
print("DevicControl Policy")
pprint.pprint(dc)
