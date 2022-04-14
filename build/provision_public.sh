#!/usr/bin/bash
systemctl stop zpa-connector
#Run AMI with IAM role that has permission to read parameters from SSM
#Will enumerate the region and VPC the client is in.  Provided there is a provisioning Key to match, will download the key and create the object in /opt/zscaler/var
#will then enrol in to ZPA and set the ConnectorID in the AMI TAG

REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
URL="http://169.254.169.254/latest/meta-data/network/interfaces/macs/"
MAC=$(curl -s $URL)
URL=$URL$MAC"vpc-id/"
VPC=$(curl -s $URL)
key=$REGION"-"$VPC
instanceid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

client_secret=$(aws ssm get-parameter --name ZSAC-ClientSecret --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
client_id=$(aws ssm get-parameter --name ZSAC-ClientID --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
company=$(aws ssm get-parameter --name ZSAC-CompanyID --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
zscaler_base=$(aws ssm get-parameter --name ZSAC-Base --query Parameter.Value --with-decryption --region $REGION | tr -d '"')

POST="client_id="$client_id"&client_secret="$client_secret
bearer=$(curl -s https://$zscaler_base/signin -d $POST -H "Content-Type: application/x-www-form-urlencoded" | jq -r .access_token)
URL='https://'$zscaler_base'/mgmtconfig/v1/admin/customers/'$company'/associationType/CONNECTOR_GRP/provisioningKey?page=1&pagesize=20&search='$key
curl -s $URL -H "Authorization: Bearer $bearer" | jq -r .list[0].provisioningKey > /opt/zscaler/var/provision_key
systemctl start zpa-connector
sleep 10
connectorid=$(openssl x509 -in /opt/zscaler/var/cert.pem -subject -noout | cut -f 3 -d \/ | cut -f 1 -d \. | cut -f 2 -d \-)
aws ec2 create-tags --resources $instanceid --tags Key="ConnectorID",Value=$connectorid