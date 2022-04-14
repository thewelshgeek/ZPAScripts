#!/usr/bin/python3
#
# Copyright 2021 Zscaler - Mark Ryan
# SPDX-License-Identifier: Apache-2.0
#

import requests, os, subprocess, boto3, tempfile, base64
from edgeutils import ApiSession

#Get AWS Environment
region=requests.get("http://169.254.169.254/latest/meta-data/placement/region").text
session = boto3.session.Session()
ssm=session.client('ssm',region_name=region)

#Retrieve ZWS Parameters from SSM
Key=ssm.get_parameter(Name='ZWS-Key',WithDecryption=True)['Parameter']['Value']
Cert=ssm.get_parameter(Name='ZWS-Cert',WithDecryption=True)['Parameter']['Value']
ClientID=ssm.get_parameter(Name='ZWS-ClientID',WithDecryption=True)['Parameter']['Value']
ClientSecret=ssm.get_parameter(Name='ZWS-ClientSecret',WithDecryption=True)['Parameter']['Value']
SiteID=ssm.get_parameter(Name='ZWS-SiteID',WithDecryption=True)['Parameter']['Value']
URLRoot=ssm.get_parameter(Name='ZWS-URLRoot',WithDecryption=True)['Parameter']['Value']

#Write certificate to disk temporarily - required for requests.get to function
cdisk = tempfile.NamedTemporaryFile(delete=False)
cdisk.write(base64.b64decode(Cert))
cdisk.close()
kdisk = tempfile.NamedTemporaryFile(delete=False)
kdisk.write(base64.b64decode(Key))
kdisk.close()
config={'url_root':"HTTPS://"+URLRoot, 'site_id': SiteID, 'username': ClientID, 'password': ClientSecret, 'cert_file': cdisk.name, 'key_file': kdisk.name}

#Create API Session
api = ApiSession(config)

#Query ZWS API for Installers - Download RHEL Latest Version
installers = api.get('installers')
for installer in installers:
    if installer['distroName']=='RHEL':
        params="x-auth-token="+requests.utils.quote(installer['authToken'])
        uri=installer['uri']
        fileName=installer['fileName']
        download=requests.get(uri,params=params)
        if download.status_code == 200:
            with open("./"+fileName, 'wb') as out_file:
                out_file.write(download.content)
        break

os.unlink(cdisk.name)
os.unlink(kdisk.name)

#install RPM and set SiteID
process=subprocess.run(['yum','-y','--nogpgcheck','install','/tmp/'+fileName])
process=subprocess.run(['/opt/edgewise/bin/edgewise_setup','--set-site-id',SiteID])