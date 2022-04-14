#!/usr/bin/bash
systemctl stop zpa-connector
instanceid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
connectorid=$(aws ec2 describe-tags --filters "Name=key,Values=ConnectorID" "Name=resource-id,Values="$instanceid | jq -r .Tags[0].Value)

REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

client_secret=$(aws ssm get-parameter --name ZSAC-ClientSecret --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
client_id=$(aws ssm get-parameter --name ZSAC-ClientID --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
company=$(aws ssm get-parameter --name ZSAC-CompanyID --query Parameter.Value --with-decryption --region $REGION | tr -d '"')
zscaler_base=$(aws ssm get-parameter --name ZSAC-Base --query Parameter.Value --with-decryption --region $REGION | tr -d '"')

POST="client_id="$client_id"&client_secret="$client_secret
bearer=$(curl -s https://$zscaler_base/signin -d $POST -H "Content-Type: application/x-www-form-urlencoded" | jq -r .access_token)
URL='https://'$zscaler_base'/mgmtconfig/v1/admin/customers/'$company'/connector/'$connectorid
curl -s -X DELETE $URL -H "Authorization: Bearer $bearer"
rm -rf /opt/zscaler/var/*