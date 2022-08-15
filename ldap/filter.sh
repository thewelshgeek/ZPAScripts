#/bin/bash
tshark -r $1  -2 -n -Tjson -x -E header=y -e "ldap.type" -e kerberos.cipher -e smb2.cmd -e smb2.sesid -e smb2.msg_id -e _ws.col.Protocol -e _ws.col.Info -e data -e smb2.signature -e ldap.objectName -e ldap.attributes -e ldap.AttributeValue -e smb2.nt_status -e http.response.code -e http.request.method -e ldap.attributeDesc -e ldap.assertionValue -e ldap.AttributeDescription -e mscldap.forest -e mscldap.domain -e mscldap.clientsitename -e mscldap.sitename -e mscldap.nb_hostname -e mscldap.nb_domain -e mscldap.hostname -e kerberos.CNameString -e kerberos.SNameString -e smb2.fid -e smb2.tree -e smb.dfs.referral.domain_name -e smb2.filename -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e dns.a -e frame.number -e smb.dfs.referral.domain_name -e dns.a -e dns.qry.name -e dns.resp.name -e dns.qry.type -e ldap.protocolOp "ldap || dns.qry.name contains "$2" || cldap || smb || smb2 || kerberos" >ts.json
/usr/bin/python3 ts-ascii.py


