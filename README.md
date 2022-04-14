# ZPAScripts
Zscaler Private Access scripts for building ZPA Environments on AWS
API for creating Segments, querying and updating
Mostly coded in Python.  Some Powershell and some BASH.

The contents of this Git Repoisitory are entirely unsupported by Zscaler Inc, and solely my own work for deploying ZIA and ZPA.  Happy to take feedback, but don't expect support responses from me either.

build - Scripts to build custom App Connector image in AWS.  This is an unsupported image (i.e. do not contact Zscaler Support about issues with this image). It is semi-hardened.  Will Automatically build a CENTOS7 image with latest App Connector binary, which could then be replicated across your AWS regions.  Includes diagnostics reporting tool, and provisioning/deprovisioning scripts API to pull Provisioning key, and ZWS configuration plus latest ZWS image.  AWS AMI for build needs to have IAM User with access to keys.  Looks up Availability Zone, Region, and pulls PK with appropriate name from ZPA.

create-zpa-environment - CloudFormaiton scripts to build out ZPA environment and ZWS environment.  Builds App Connectors, lambda functions, then installs RAILS evironment.  Uses AMI created above.  Could pass provisioning scripts though userdata.  Main point of these scripts - Provisioning key is not passed in UserData - instead the API keys are passed from SystemsManagement variables in AWS, which are used to create provisioning keys dynamically.

cloud-connector - CFN Templates for Cloud Connector.  AWS API Scripts to run to update Route53 DNS directly, and save re-running CFN.

LDAP - CLDAP tool to run on App Connectors.  Uses PyLDAP to build UDP LDAP connection.  Query Active Directory for availability.  LDAP lookup of domain controllers.  CLDAP Bind to Domain Controllers to test connectivity and return which AD Site the Domain Controller returns.  This can be run from App Connectors to ensure App Connectors are correctly registered in AD Site.  

Public - A Couple of Python3 Scripts.  Require pyldap, requests and json modules to be installed in Python3.
1. activedirectory.py Query Active Directory for Domain Controllers.  Create App Segment containing all Domain Controllers and Default Ports.
2. sapcreate.py Take a SAP Packet Capture.  Parse it with SPA Disector to output SAP hostnames.  Create App Segment for SAP based on output.  Takes the guesswork out of how SAP is configured.
3. computers.py - LDAP query Active Directory for computers objects.  Filter objects based on RegEx.  Create an Application Segment containing all the computer FQDN's matching the RegEx.  Allows for automatic creation of segment for Remote Support

SCIM - SCIM client.  100% Unsupported by Zscaler Support - do not contact Zscaler Support for any issues with this.  Requires pyldap, requests, json modules to be installed in Python3.
Generate a SCIM Endpoint and Bearer token in the IDP Configuration for ZIA and ZPA.  The client connects to Active Directory and enumerates a single group containing all nested groups to be synchronised.  "Top Level Groups" (i.e. those in the single group) will be passed to Zscaler.  All members of the groups (i.e. nested) will be returned in a flattened format.  (i.e. group1 contains group2 and group3, group 2 contains user1; group 3 contains user 5 - this will return group 1 containing user 1 and user 5).

ZIA - Powershell to be run on client machine.  Initiates an IDP Initiated SSO request which will update groups.  Avoids SCIM / LDAP sync, where ZCC doesn't have functionality to re-authenticate users.

