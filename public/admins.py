import time, requests, json, sys, yaml

def obfuscateApiKey (seed):
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]
    print("Timestamp:", now, "\tKey", key)
    return [now, key]

with open('configbeta.yaml') as f:
    config = yaml.safe_load(f)

username=config['ziausername']
password=config['ziapassword']
seed=config['apikey']

#Setup Parameters
base='https://zsapi.zscalerbeta.net/api/v1'
timestamp, apiKey = obfuscateApiKey(seed)

data={'apiKey':apiKey,'username':username,'password':password,'timestamp':timestamp}
headers={'Accept':'*/*','Content-Type':'application/json'}

#Logon and retrieve cookie
logon=requests.post(base+'/authenticatedSession',data=json.dumps(data),headers=headers)
cookie_jar = requests.cookies.RequestsCookieJar()
cookie_jar.update(logon.cookies)

admins=json.loads(requests.get(base+'/adminUsers',cookies=cookie_jar,headers=headers).content)

#Retrieve user list, where users are in group "Zscaler Admins"
users=json.loads(requests.get(base+'/users?group=ZscalerAdmins',cookies=cookie_jar,headers=headers).content)

#For each administrator - check if a corresponding user exists. 
#If the user exists, update the Administrator with a Scope of Department, where Department is taken from the User 
for admin in admins:
    for user in users:
        if user['id']==admin['id']:
            updateid=user['id']
            update={}
            update['loginName']=admin['loginName']
            update['userName']=admin['userName']
            update['email']=admin['email']
            update['role']={}
            update['role']['id']=admin['role']['id']
            update['adminScopeType']='DEPARTMENT'
            update['adminScopeScopeEntities']=[user['department']]
            update['disabled']=False
            print(update)
            r=requests.put(base+'/adminUsers/'+str(updateid),data=json.dumps(update),cookies=cookie_jar,headers=headers)

#Activate Changes 
activate=requests.post(base+'/status/activate',cookies=cookie_jar,headers=headers)
print(str(activate.content))
#Kill Session
end=requests.delete(base+'/authenticatedSession',cookies=cookie_jar, headers=headers)
