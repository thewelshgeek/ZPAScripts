#!/usr/bin/python3
import json, codecs

with open('./ts.json') as f:
    ts = json.load(f)

dns=[]
#Firstpass - Get DNS Answers.  Second Pass, insert DNS into JSON.
for a in range(len(ts)):
	if 'dns.a' in ts[a]['_source']['layers']:
		data=ts[a]['_source']['layers']
		for b in range(len(data['dns.resp.name'])):
			try:
				fqdn={'fqdn':data['dns.resp.name'][b],'ip':data['dns.a'][b]}
			except:
				if data['dns.qry.type']=='6':
					fqdn={'fqdn':data['dns.resp.name'][b],'ip':'SOA'}
			found=False
			for each in dns:
				if each['fqdn']==fqdn['fqdn']:
					found=True
			if not found:
				dns.append(fqdn)

errors=[]
messageID=''
for a in range(len(ts)):
	if 'ldap.AttributeValue' in ts[a]['_source']['layers']:
		if ':' in ts[a]['_source']['layers']['ldap.AttributeValue'][0]:
			for b in range(len(ts[a]['_source']['layers']['ldap.AttributeValue'])):
				attribute=ts[a]['_source']['layers']['ldap.AttributeValue'][b]
				try:
					attribute=codecs.decode(attribute.replace(':',''),"hex").decode('utf-8')
				except:
					False
				ts[a]['_source']['layers']['ldap.AttributeValue'][b]=attribute
	if 'smb2.signature' in ts[a]['_source']['layers']:
		if 'data' in ts[a]['_source']['layers']:
			data=ts[a]['_source']['layers']['data'][0]
			try:
				data=codecs.decode(data,"hex").decode('utf-8')
			except:
				False
			ts[a]['_source']['layers']['data'][0]=data
		if 'Error' in ts[a]['_source']['layers']['_ws.col.Info'][0]:
			data=json.loads('{}')
			if 'smb2.signature' in ts[a]['_source']['layers']:
				if 'Error' in ts[a]['_source']['layers']['_ws.col.Info'][0]:
					data=json.loads('{}')
					if 'smb2.signature' in ts[a]['_source']['layers']:
						if 'Error' in ts[a]['_source']['layers']['_ws.col.Info'][0]:
							data=json.loads('{}')
							error={'Error Response':ts[a]['_source']['layers']['_ws.col.Info'][0]}
							data.update(error)
							for b in range(a):
								if 'smb2.msg_id' in ts[b]['_source']['layers'] and 'smb2.cmd' in ts[b]['_source']['layers']:
									if ts[b]['_source']['layers']['smb2.msg_id'][0]==ts[a]['_source']['layers']['smb2.msg_id'][0]:
										error={'Error Request':ts[b]['_source']['layers']['_ws.col.Info'][0]}
										data.update(error)
									if ts[b]['_source']['layers']['smb2.cmd'][0]=='1' and ts[b]['_source']['layers']['smb2.sesid'][0]==ts[a]['_source']['layers']['smb2.sesid'][0]:
										messageID=ts[b]['_source']['layers']['smb2.msg_id']
										sesid=ts[b]['_source']['layers']['smb2.sesid'][0]
							for c in range(a):
								if 'smb2.msg_id' in ts[c]['_source']['layers'] and 'smb2.cmd' in ts[c]['_source']['layers']:
									if ts[c]['_source']['layers']['smb2.cmd'][0]=='1' and ts[c]['_source']['layers']['smb2.msg_id']==messageID:
										if 'NTLM' in ts[c]['_source']['layers']['_ws.col.Info'][0]:
											if 'User' in  ts[c]['_source']['layers']['_ws.col.Info'][0]:
												user=ts[c]['_source']['layers']['_ws.col.Info'][0].split(': ')[1]
											error={'Ticket':'NTLM'}
											data.update(error)
											error={'User':user}
											data.update(error)
											error={'Session':sesid}
											data.update(error)
										elif 'Session Setup Response' in ts[c]['_source']['layers']['_ws.col.Info'][0]:
											error={'Ticket':'NTLM'}
											for each in errors:
												if 'Session' in each:
													if each['Session']==messageID:
														error={'Session':sesid}
														data.update(error)
														error={'User':each['User']}
														data.update(error)
										else:
											cipher=ts[c]['_source']['layers']['kerberos.cipher'][0]
											for d in range(c):
												if 'TGS-REP' in ts[d]['_source']['layers']['_ws.col.Info'][0]:
													error={'Ticket':ts[d]['_source']['layers']['kerberos.CNameString'][0]}
													data.update(error)
							errors.append(data)
	if 'http.response.code' in ts[a]['_source']['layers']:
		if 'data' in ts[a]['_source']['layers']:
			data=ts[a]['_source']['layers']['data'][0]
			try:
				data=codecs.decode(data,"hex").decode('utf-8')
			except:
				False
			ts[a]['_source']['layers']['data'][0]=data
	if ts[a]['_source']['layers']['ip.src'][0].startswith('100.64'):
		IP=ts[a]['_source']['layers']['ip.src'][0]
		for each in dns:
			if each['ip']==IP:
				ts[a]['_source']['layers']['hostname.src']=each['fqdn']
	if ts[a]['_source']['layers']['ip.dst'][0].startswith('100.64'):
		IP=ts[a]['_source']['layers']['ip.dst'][0]
		for each in dns:
			if each['ip']==IP:
				ts[a]['_source']['layers']['hostname.dst']=each['fqdn']
			
with open('./errors.json', 'w') as outfile:
    json.dump(errors, outfile, indent=4)			

with open('./dns.json', 'w') as outfile:
    json.dump(dns, outfile, indent=4)

with open('./ts.json', 'w') as outfile:
    json.dump(ts, outfile, indent=4)
