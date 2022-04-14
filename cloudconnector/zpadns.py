#!/usr/bin/python3
import boto3, yaml

with open('config.yaml') as f:
    config = yaml.safe_load(f)

#Take input of ENI of Cloud Connector Service Interface
#Create Route53 Entries necessary to process ZPA Traffic

aws_access_key_id=config['aws_access_key_id']
aws_secret_access_key=config['aws_secret_access_key']

ENI=input("ENI of CC Service IP : ")

client = boto3.client('ec2', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
response = client.describe_network_interfaces(NetworkInterfaceIds=[ENI])
TargetIp=response.get('NetworkInterfaces')[0].get('PrivateIpAddresses')[1]['PrivateIpAddress']
VpcId= response.get('NetworkInterfaces')[0].get('VpcId')
SubnetId= response.get('NetworkInterfaces')[0].get('SubnetId')

securitygroups=client.describe_security_groups()
GroupId=''
for securitygroup in securitygroups['SecurityGroups']:
	if securitygroup['VpcId']==VpcId:
		if securitygroup['GroupName']=='ZPA App Segment Resolver':
			GroupId=securitygroup['GroupId']

if GroupId=='':
	securitygroup = client.create_security_group(
	    Description='Enable app segment resolver comm',
	    GroupName='ZPA App Segment Resolver',
	    VpcId=VpcId
	)
	GroupId=securitygroup.get('GroupId')

	client.authorize_security_group_ingress(
		GroupId=GroupId,
		IpPermissions=[
	        {
	            'FromPort': 0,
	            'IpProtocol': '-1',
	            'IpRanges': [
	                {
	                    'CidrIp': '0.0.0.0/0',
	                    'Description': 'All Inbound',
	                },
	            ],
	            'ToPort': 65535,
	        },
	    ],
	)


client = boto3.client('route53resolver', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

resolver_endpoint = client.create_resolver_endpoint(
    CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver',
    Name='ZSCCAppSegmentResolver',
    SecurityGroupIds=[
        GroupId,
    ],
    Direction='OUTBOUND',
    IpAddresses=[
        {
            'SubnetId': SubnetId
        },
        {
            'SubnetId': SubnetId
        },
    ],
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCCAppSegmentResolver'
        },
    ]
)

DomainName="zscalerbeta.net"
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='ZIA_Association',
    VPCId=VpcId
)

DomainName='zscaler.com'
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='Zscaler_Association',
    VPCId=VpcId
)

DomainName='freebsd.org'
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='BSD_Association',
    VPCId=VpcId
)
DomainName='ntp.org'
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='NTP_Association',
    VPCId=VpcId
)
DomainName='amazonaws.com'
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='Amazon_Association',
    VPCId=VpcId
)


DomainName='zpabeta.net'
resolver_rule = client.create_resolver_rule(
  CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='SYSTEM',
    DomainName=DomainName,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCloudRule'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='ZPA_Association',
    VPCId=VpcId
)

