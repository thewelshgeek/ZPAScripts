import time, requests, json, sys
 
def obfuscateApiKey ():
    seed = '{SEED}'
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]
    return key 

argv=sys.argv[1:]
command=''
if argv==[]:
    print('userdelete.py [userid]')
    sys.exit()
if len(argv)>1:
    print('usersdelete.py [userid]')
    sys.exit()
usertodelete=argv[0]

with open('configbeta.yaml') as f:
    config = yaml.safe_load(f)

username=config['ziausename']
password=config['ziapassword']

#Setup Parameters
base='https://zsapi.zscalerbeta.net/api/v1'
timestamp=str(int(time.time()*1000))
apiKey= obfuscateApiKey()
data={'apiKey':apiKey,'username':username,'password':password,'timestamp':timestamp}
headers={'Accept':'*/*','Content-Type':'application/json'}

#Logon and retrieve cookie
logon=requests.post(base+'/authenticatedSession',data=json.dumps(data),headers=headers)
cookie_jar = requests.cookies.RequestsCookieJar()
cookie_jar.update(logon.cookies)

#Retrieve user list
users=json.loads(requests.get(base+'/users',cookies=cookie_jar,headers=headers).content)

#Search for user mryan@welshgeek.net, delete user from table
for user in users:
	if user['email']==usertodelete:
		userid=user['id']
		delete=requests.delete(base+'/users/'+str(userid), cookies=cookie_jar, headers=headers)
		print('Deleted User : '+str(user['email']))
	
#Activate Changes 
activate=requests.post(base+'/status/activate',cookies=cookie_jar,headers=headers)
print(str(activate.content))
#Kill Session
end=requests.delete(base+'/authenticatedSession',cookies=cookie_jar, headers=headers)
