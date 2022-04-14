#!/usr/bin/python3
import boto3, yaml


with open('config.yaml') as f:
    config = yaml.safe_load(f)

#Take input of ENI of Cloud Connector Service Interface, and FQDN of ZPA App Segment
#Create Creates the Route53 rule to pass the DNS request to the Cloud Connector ENI

aws_access_key_id=config['aws_access_key_id']
aws_secret_access_key=config['aws_secret_access_key']

ENI=input("ENI of CC Service IP : ")
DomainName=input("FQDN of Application : ")

client = boto3.client('ec2', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
response = client.describe_network_interfaces(NetworkInterfaceIds=[ENI])
TargetIp=response.get('NetworkInterfaces')[0].get('PrivateIpAddresses')[1]['PrivateIpAddress']
VpcId= response.get('NetworkInterfaces')[0].get('VpcId')

client = boto3.client('route53resolver', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

ResolverEndpoints = client.list_resolver_endpoints(
    Filters=[
        {
            'Name': 'Name',
            'Values': ['ZSCCAppSegmentResolver']
        }
    ]
)

ResolverEndpointId=ResolverEndpoints['ResolverEndpoints'][0]['Id']

resolver_rule = client.create_resolver_rule(
	CreatorRequestId=VpcId+'_ZSCCAppSegmentResolver_'+DomainName,
    Name='ZSCCAppSegmentResolver',
    RuleType='FORWARD',
    DomainName=DomainName,
    TargetIps=[
        {
            'Ip': TargetIp,
            'Port': 53
        },
        {
            'Ip': TargetIp,
            'Port': 53
        },
    ],
    ResolverEndpointId=ResolverEndpointId,
    Tags=[
        {
            'Key': 'Function',
            'Value': 'ZSCCAppSegmentResolver'
        },
    ]
)

resolver_associate = client.associate_resolver_rule(
    ResolverRuleId=resolver_rule['ResolverRule']['Id'],
    Name='ZSCCAppSegmentResolver_Association',
    VPCId=VpcId
)
