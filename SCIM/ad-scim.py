#!/usr/bin/python3
import ldap, requests, json, datetime, base64, time, yaml, sys

def scimcreate(Endpoint, Headers, Data):
	create=requests.post(Endpoint,headers=Headers,data=json.dumps(Data))
	if create.status_code==201:
		created=json.loads(create.content)
		createdid=created['id']
	else:
		createdid='null'
	return createdid

def scimdelete(Endpoint, Headers):
	delete=requests.delete(Endpoint+'',headers=Headers)

def scimupdate(Endpoint, Headers, Data):
	update=requests.put(Endpoint, headers=Headers,data=json.dumps(Data))
	if update.status_code==200:
		updated=json.loads(update.content)
		updatedid=updated['id']
	else:
		updatedid='null'
	return updatedid

def calcGUID(hexguid):
	return hexguid[6:8]+hexguid[4:6]+hexguid[2:4]+hexguid[0:2]+'-'+hexguid[10:12]+hexguid[8:10]+'-'+hexguid[14:16]+hexguid[12:14]+'-'+hexguid[16:20]+'-'+hexguid[20:]

with open('config.yaml') as f:
    config = yaml.safe_load(f)

#Read Users from LDAP
#Read Groups from LDAP (Top Group Zscaler contains all Groups to Sync)
#Flatten Groups - Enumerate Nested Groups - return users in all nested groups from top.
#Push Users via SCIM - Update User dictionary with Zscaler UserID
#Create Group Object - Members are Zscaler UserID's
#Push Groups via SCIM

ZIAEndpoint=config['ZIAEndpoint']
ZIABearer=config['ZIABearer']
ziaheaders={'Authorization':'Bearer '+ZIABearer}
ZPAEndpoint=config['ZPAEndpoint']
ZPABearer=config['ZPABearer']
zpaheaders={'Authorization':'Bearer '+ZPABearer}
BindHostPort=config['BindHostPort']
BindUsername=config['BindUsername']
BindPassword=config['BindPassword']
BindDN=config['BindDN']
TopGroupDN=config['TopGroupDN']

currentdatetime=datetime.datetime.utcnow()
ldaptime=currentdatetime.strftime('%Y%m%d%H%M%S.0Z')


argv=sys.argv[1:]
command=''
if argv==[]:
	print('scim.py [Create|Update|DeleteAll]')
	sys.exit()
for opt in argv:
  if opt in ("C", "Create"):
     command='Create'
  elif opt in ("U", "Update"):
     command = 'Update'
  elif opt in ("D", "DeleteAll"):
     command = 'DeleteAll'
  else:
     print('scim.py [Create|Update|DeleteAll]')
     sys.exit()



l = ldap.initialize('ldap://'+BindHostPort)
bind=l.bind(BindUsername,BindPassword)
time.sleep(1)

users=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:='+TopGroupDN+'))',['userPrincipalName','memberOf','department','displayName','objectGUID','whenChanged','userAccountControl'])
topgroups=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=group)(memberOf='+TopGroupDN+'))',['distinguishedName','cn','objectGUID','whenChanged'])

#Iterate through users returned in LDAP Search
#Calculate ImmutableID from GUID
#Create JSON Object to POST to API for Create
if command=='Create':
	print('Create Users and Groups')
	scimjson={'users':[],'ziagroups':[],'zpagroups':[]}
	i=0
	for user in users:
		if bin(int(user[1]['userAccountControl'][0]))[17:18]=='0':
			userCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User':{}}
			userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['immutableId']=base64.b64encode(user[1]['objectGUID'][0]).decode('utf-8')
			userCreate['userName']=user[1]['userPrincipalName'][0].decode('utf-8')
			userCreate['externalId']=calcGUID(user[1]['objectGUID'][0].hex())
			userCreate['active']='true'
			try:
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=user[1]['department'][0].decode('utf-8')
			except:
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=""
			try:
				userCreate['displayName']=user[1]['displayName'][0].decode('utf-8')
			except:
				userCreate['displayName']=""
			ZIAID=scimcreate(ZIAEndpoint+'/Users',ziaheaders,userCreate)
			ZPAID=scimcreate(ZPAEndpoint+'/Users',zpaheaders,userCreate)
			userdata=list(users[i])
			userdata.append({'ziaid':ZIAID})
			userdata.append({'zpaid':ZPAID})
			users[i]=tuple(userdata)
			userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']=ZIAID
			userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']=ZPAID
			userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['whenSynced']=ldaptime
			userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['cn']=user[0]
			scimjson['users'].append(userCreate)
		i+=1

#Nested Group Support
#Return top group (Zscaler) - contains all top groups.
	ziagroupjson={}
	zpagroupjson={}
	i=0
	for each in topgroups:
		ziagroupCreate={}
		zpagroupCreate={}
		#for each of the top groups, enumerated members of nested groups to return users in the top group. (Basically flatten the nested groups)
		members=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:='+each[0]+'))',['cn'])
		if len(members)>0:
			#Create a list for each of ZIA and ZPA, which contains the user IDs.  Groups are lists of users, rather than users being in groups
			ziamemberdata=[]
			zpamemberdata=[]
			for member in members:
				for user in users:
					if member[0]==user[0] and bin(int(user[1]['userAccountControl'][0]))[17:18]=='0':
						ziads={'value':user[2]['ziaid']}
						ziamemberdata=ziamemberdata+[ziads]
						zpads={'value':user[3]['zpaid']}
						zpamemberdata=zpamemberdata+[zpads]
		ziagroupCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
		zpagroupCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
		ziagroupCreate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
		zpagroupCreate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
		try:
			ziagroupCreate['displayName']=each[1]['cn'][0].decode('utf-8')
			zpagroupCreate['displayName']=each[1]['cn'][0].decode('utf-8')
		except:
			ziagroupCreate['displayName']=""
			zpagroupCreate['displayName']=""
		try:
			ziagroupCreate['members']=ziamemberdata
			zpagroupCreate['members']=zpamemberdata
		except:
			ziagroupCreate['members']=""
			zpagroupCreate['members']=""	
		ZIAGroupCreate=scimcreate(ZIAEndpoint+'/Groups',ziaheaders,ziagroupCreate)
		ZPAGroupCreate=scimcreate(ZPAEndpoint+'/Groups',zpaheaders,zpagroupCreate)
		ziagroupCreate['whenSynced']=ldaptime
		zpagroupCreate['whenSynced']=ldaptime
		ziagroupCreate['cn']=each[0]
		zpagroupCreate['cn']=each[0]
		ziagroupCreate['ZIAGROUPID']=ZIAGroupCreate
		zpagroupCreate['ZPAGROUPID']=ZPAGroupCreate
		scimjson['ziagroups'].append(ziagroupCreate)
		scimjson['zpagroups'].append(zpagroupCreate)
		i+=1
	with open('./scimdata.json', 'w') as outfile:
		json.dump(scimjson, outfile)
	outfile.close()

if command=='Update':
	x=True
	while x:
	#	Read JSON
	#	Read LDAP
	#	Compare
	#		Delete User
	#		Delete User from Group  - update Group
	#		Delete Group
		print('Update Users and Groups')
		with open('./scimdata.json', 'r') as infile:
			scimjson=json.load(infile)
		infile.close()
		newjson={'users':[],'ziagroups':[],'zpagroups':[]}
		jsonusers=scimjson['users']
		i=0
		#handle user deletes
		for user in jsonusers:
			found=False
			userimmutableId=user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['immutableId']
			for each in users:
				immutableId=base64.b64encode(each[1]['objectGUID'][0]).decode('utf-8')
				if userimmutableId==immutableId:
					found=True
			#Not Found therefore Delete
			if not found:
				scimdelete(ZIAEndpoint+'/Users/'+user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID'],ziaheaders)
				scimdelete(ZPAEndpoint+'/Users/'+user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID'],zpaheaders)
		#handle user creates/updates	
		for user in users:
			immutableId=base64.b64encode(user[1]['objectGUID'][0]).decode('utf-8')
			whenchanged=user[1]['whenChanged'][0].decode('utf-8')
			if bin(int(user[1]['userAccountControl'][0]))[17:18]=='1':
				disabled=True
			else:
				disabled=False
			found=False
			#search for user - update
			for each in jsonusers:
				if each['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['immutableId']==immutableId:
					found=True
					if each['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['whenSynced']<whenchanged:
						userUpdate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User':{}}
						userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['immutableId']=base64.b64encode(user[1]['objectGUID'][0]).decode('utf-8')
						userUpdate['userName']=user[1]['userPrincipalName'][0].decode('utf-8')
						userUpdate['externalId']=calcGUID(user[1]['objectGUID'][0].hex())
						if disabled:
							userUpdate['active']='false'
						else:
							userUpdate['active']='true'
						try:
							userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=user[1]['department'][0].decode('utf-8')
						except:
							userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=""
						try:
							userUpdate['displayName']=user[1]['displayName'][0].decode('utf-8')
						except:
							userUpdate['displayName']=""
						ZIAID=each['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']
						ZPAID=each['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']
						userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']=ZIAID
						userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']=ZPAID
						userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['whenSynced']=ldaptime
						userUpdate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['cn']=user[0]
						ZIAUPDATE=scimupdate(ZIAEndpoint+'/Users/'+ZIAID,ziaheaders,userUpdate)
						ZPAUPDATE=scimupdate(ZPAEndpoint+'/Users/'+ZPAID,zpaheaders,userUpdate)
						newjson['users'].append(userUpdate)
					else:
						newjson['users'].append(each)
					#not Found therefore Create
			if not found:
				userCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User':{}}
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['immutableId']=base64.b64encode(user[1]['objectGUID'][0]).decode('utf-8')
				userCreate['userName']=user[1]['userPrincipalName'][0].decode('utf-8')
				userCreate['externalId']=calcGUID(user[1]['objectGUID'][0].hex())
				if disabled:
					userCreate['active']='false'
				else:
					userCreate['active']='true'
				try:
					userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=user[1]['department'][0].decode('utf-8')
				except:
					userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']=""
				try:
					userCreate['displayName']=user[1]['displayName'][0].decode('utf-8')
				except:
					userCreate['displayName']=""
				ZIAID=scimcreate(ZIAEndpoint+'/Users',ziaheaders,userCreate)
				ZPAID=scimcreate(ZPAEndpoint+'/Users',zpaheaders,userCreate)
				userdata=list(users[i])
				userdata.append({'ziaid':ZIAID})
				userdata.append({'zpaid':ZPAID})
				users[i]=tuple(userdata)
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']=ZIAID
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']=ZPAID
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['whenSynced']=ldaptime
				userCreate['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['cn']=user[0]
				newjson['users'].append(userCreate)
			i+=1



	#Nested Group Support
	#Return top group (Zscaler) - contains all top groups.
		i=0
		jsonziagroups=scimjson['ziagroups']
		jsonzpagroups=scimjson['zpagroups']
		jsonusers=newjson['users']
		for each in topgroups:
			found=False
			userfound=False
			ziagroupUpdate={}
			zpagroupUpdate={}
			groupschanged=[]
			#for each of the top groups, check if any of the nested groups have changed.  If the nested groups have changed, then update (the entire group - this could be optimised)
			for jsongroup in jsonziagroups:
				if each[0]==jsongroup['cn']:
					found=True
					FoundZIAID=jsongroup['ZIAGROUPID']
					groupschanged=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=group)(memberOf:1.2.840.113556.1.4.1941:='+jsongroup['cn']+')(whenChanged>='+jsongroup['whenSynced']+'))')
					ZIAData=jsongroup
					for user in users:
						#search for the user in a group has a group change date been updated since the group was last synced (i.e. user added/deleted)
						userschanged=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=group)(distinguishedName='+jsongroup['cn']+')(member:1.2.840.113556.1.4.1941:='+user[0]+'))',['whenChanged'])
						if len(userschanged)>0:
							modifieddate=userschanged[0][1]['whenChanged'][0].decode('utf-8')
							lastsynceddate=jsongroup['whenSynced']
							if modifieddate<lastsynceddate:
								userfound=True
			for jsongroup in jsonzpagroups:
				if each[0]==jsongroup['cn']:
					found=True
					if len(groupschanged)==0:
						groupschanged=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=group)(memberOf:1.2.840.113556.1.4.1941:='+jsongroup['cn']+')(whenChanged>='+jsongroup['whenSynced']+'))')
					FoundZPAID=jsongroup['ZPAGROUPID']
					ZPAData=jsongroup
					for user in users:
						#search for the user in a group has a group change date been updated since the group was last synced (i.e. user added/deleted)
						userschanged=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=group)(distinguishedName='+jsongroup['cn']+')(member:1.2.840.113556.1.4.1941:='+user[0]+'))',['whenChanged'])
						if len(userschanged)>0:
							modifieddate=userschanged[0][1]['whenChanged'][0].decode('utf-8')
							lastsynceddate=jsongroup['whenSynced']
							if modifieddate<lastsynceddate:
								userfound=True
			#if any of the nested groups have changed or the user had been added to a group, then enumerated members of nested groups to return users in the top group. (Basically flatten the nested groups)
			if (len(groupschanged)>0 or userfound) and found:
				members=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:='+each[0]+'))',['cn'])
				ziamemberdata=[]
				zpamemberdata=[]
				if len(members)>0:
					#Create a list for each of ZIA and ZPA, which contains the user IDs.  Groups are lists of users, rather than users being in groups
					for member in members:
						for user in jsonusers:
							if member[0]==user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['cn']:
								ziads={'value':user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']}
								ziamemberdata=ziamemberdata+[ziads]
								zpads={'value':user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']}
								zpamemberdata=zpamemberdata+[zpads]
					ziagroupUpdate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
					zpagroupUpdate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
					ziagroupUpdate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
					zpagroupUpdate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
					try:
						ziagroupUpdate['displayName']=each[1]['cn'][0].decode('utf-8')
						zpagroupUpdate['displayName']=each[1]['cn'][0].decode('utf-8')
					except:
						ziagroupUpdate['displayName']=""
						zpagroupUpdate['displayName']=""
					try:
						ziagroupUpdate['members']=ziamemberdata
						zpagroupUpdate['members']=zpamemberdata
					except:
						ziagroupUpdate['members']=""
						zpagroupUpdate['members']=""
					ZIAGroupUpdate=scimupdate(ZIAEndpoint+'/Groups/'+FoundZIAID,ziaheaders,ziagroupUpdate)
					ZPAGroupUpdate=scimupdate(ZPAEndpoint+'/Groups/'+FoundZPAID,zpaheaders,zpagroupUpdate)
					ziagroupUpdate['whenSynced']=ldaptime
					zpagroupUpdate['whenSynced']=ldaptime
					ziagroupUpdate['cn']=each[0]
					zpagroupUpdate['cn']=each[0]
					ziagroupUpdate['ZIAGROUPID']=ZIAGroupUpdate
					zpagroupUpdate['ZPAGROUPID']=ZPAGroupUpdate
					newjson['ziagroups'].append(ziagroupUpdate)
					newjson['zpagroups'].append(zpagroupUpdate)
				else:				
					scimdelete(ZIAEndpoint+'/Groups/'+jsongroup['ZIAGROUPID'])
					scimdelete(ZPAEndpoint+'/Groups/'+jsongroup['ZPAGROUPID'])
			#Else New Group to be created 
			elif len(groupschanged)>0 and not found:
				users=newjson['users']
				members=l.search_s(BindDN,ldap.SCOPE_SUBTREE,'(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:='+each[0]+'))',['cn'])
				if len(members)>0:
					#Create a list for each of ZIA and ZPA, which contains the user IDs.  Groups are lists of users, rather than users being in groups
					ziamemberdata=[]
					zpamemberdata=[]
					for member in members:
						for user in users:
							if member[0]==user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['cn']:
								ziads={'value':user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZIAID']}
								ziamemberdata=ziamemberdata+[ziads]
								zpads={'value':user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['ZPAID']}
								zpamemberdata=zpamemberdata+[zpads]
				ziagroupCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
				zpagroupCreate={'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
				ziagroupCreate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
				zpagroupCreate['externalId']=calcGUID(each[1]['objectGUID'][0].hex())
				try:
					ziagroupCreate['displayName']=each[1]['cn'][0].decode('utf-8')
					zpagroupCreate['displayName']=each[1]['cn'][0].decode('utf-8')
				except:
					ziagroupCreate['displayName']=""
					zpagroupCreate['displayName']=""
				try:
					ziagroupCreate['members']=ziamemberdata
					zpagroupCreate['members']=zpamemberdata
				except:
					ziagroupCreate['members']=""
					zpagroupCreate['members']=""	
				ZIAGroupCreate=scimcreate(ZIAEndpoint+'/Groups',ziaheaders,ziagroupCreate)
				ZPAGroupCreate=scimcreate(ZPAEndpoint+'/Groups',zpaheaders,zpagroupCreate)
				ziagroupCreate['whenSynced']=ldaptime
				zpagroupCreate['whenSynced']=ldaptime
				ziagroupCreate['cn']=each[0]
				zpagroupCreate['cn']=each[0]
				ziagroupCreate['ZIAGROUPID']=ZIAGroupCreate
				zpagroupCreate['ZPAGROUPID']=ZPAGroupCreate
				newjson['ziagroups'].append(ziagroupCreate)
				newjson['zpagroups'].append(zpagroupCreate)
			elif len(groupschanged)==0 and found:
				newjson['ziagroups'].append(ZIAData)
				newjson['zpagroups'].append(ZPAData)
			i+=1

		with open('./scimdata.json', 'w') as outfile:
			json.dump(newjson, outfile)
		outfile.close()
		print('Completed')
		time.sleep(30)


	

if command=='DeleteAll':
	print('DeleteAll Users and Groups')
	ZIAGroups=json.loads(requests.get(ZIAEndpoint+'/Groups',headers=ziaheaders).content)['Resources']
	for i in ZIAGroups:
		if i['displayName']!='Service Admin':
			URL=i['meta']['location']
			requests.delete(URL,headers=ziaheaders)
	ZPAGroups=json.loads(requests.get(ZPAEndpoint+'/Groups',headers=zpaheaders).content)
	if ZPAGroups['totalResults']>0:
		for i in ZPAGroups['Resources']:
			URL=i['meta']['location']
			requests.delete(URL,headers=zpaheaders)			
	ZIAUsers=json.loads(requests.get(ZIAEndpoint+'/Users',headers=ziaheaders).content)['Resources']
	for i in ZIAUsers:
		try:
			if 'department' in i:
				if i['department']!='Service Admin':
						URL=i['meta']['location']
						requests.delete(URL,headers=ziaheaders)
			else:
				URL=i['meta']['location']
				requests.delete(URL,headers=ziaheaders)
		except:
			URL=i['meta']['location']
	ZPAUsers=json.loads(requests.get(ZPAEndpoint+'/Users',headers=zpaheaders).content)
	if ZPAUsers['totalResults']>0:
		for i in ZPAUsers['Resources']:
			URL=i['meta']['location']
			requests.delete(URL,headers=zpaheaders)
	
l.unbind()