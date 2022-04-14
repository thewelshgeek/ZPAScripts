#!/bin/bash

#REQUIRED_RPMS=(yum-plugin-fastestmirror ruby ruby-devel kpartx)
CFG_FILE=$HOME/.centos-ami-builder

## Builder functions ########################################################


build_ami() {
	get_root_device
	make_build_dirs
	make_img_file
	mount_img_file
	install_packages
	make_fstab
	setup_network
	setup_scripts
	install_grub
#	enter_shell
	harden_image
	unmount_all
	snapshot_volume
	register_snapshot
#	launch_instance
	quit
}


# Determine what device our root partition is mounted on, and get its UUID
get_root_device() {
	read ROOT_DEV ROOT_FS_TYPE <<< $(awk '/^\/dev[^ ]+ \/ / {print $1" "$3}' /proc/mounts)
	[[ $ROOT_FS_TYPE == "xfs" ]] || fatal "Root file system on build host must be XFS (is $ROOT_FS_TYPE)"
	ROOT_UUID=$(/sbin/blkid -o value -s UUID $ROOT_DEV)
	echo "Build host root device: $ROOT_DEV, UUID: $ROOT_UUID"
}


# Create the build hierarchy.  Unmount existing paths first, if need by
make_build_dirs() {

	AMI_ROOT=$BUILD_ROOT
	AMI_MNT="/mnt/ec2-image"
	AMI_SIZE=4000
	AMI_DEV=xvdf
	AMI_DEV_PATH=/dev/$AMI_DEV
	AMI_PART_PATH=${AMI_DEV_PATH}1
	AMI_IMG=${AMI_DEV_PATH}


	output "Creating build hierarchy in $AMI_ROOT..."

	if grep -q "^[^ ]\+ $AMI_MNT" /proc/mounts; then
		yesno "$AMI_MNT is already mounted; unmount it"
		unmount_all
	fi

	mkdir -p $AMI_MNT || fatal "Unable to create create build hierarchy"

}


# Create our image file
make_img_file() {

	output "Creating image fille $AMI_IMG..."
	if [[ -e $AMI_DEV_PATH ]]; then
		yesno "$AMI_DEV_PATH is already defined; redefine it"
		undefine_hvm_dev
	fi
	[[ -f $AMI_IMG ]] && yesno "$AMI_IMG already exists; overwrite it"

	# Create a primary partition
	# Check Availability Zone of build AMI, create a volume in the same Availability Zone and attach to build AMI
	AZ=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone)
	REGION=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')
	VID=$(aws ec2 create-volume --size 4 --availability-zone $AZ --volume-type gp2 | grep VolumeId | cut -d \" -f4)
	IID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
	output "AvailabilityZone=$AZ"
	output "Region=$REGION"
	sleep 10s
	output "Mounting $VID on $IID"
	aws ec2 attach-volume --volume-id $VID --instance-id $IID --device /dev/sdf
	output "sleeping 60s for volume to mount"
	sleep 60s

	# Create partition on EBS Volume
	parted $AMI_IMG --script -- "mktable msdos mkpart primary xfs 2 100% quit" 
	sync; udevadm settle

	# Create our xfs partition and clone our builder root UUID onto it
	# Setting UUID metadata on XFS necessary for Grub Install
	mkfs.xfs  -m uuid=$ROOT_UUID -f -L root $AMI_PART_PATH  || \
		fatal "Unable to create XFS filesystem on $AMI_PART_PATH"
	xfs_admin -U $ROOT_UUID $AMI_PART_PATH  || \
		fatal "Unable to assign UUID '$ROOT_UUID' to $AMI_PART_PATH"
	sync

}


# Mount the image file and create and mount all of the necessary devices
mount_img_file()
{
	output "Mounting image file $AMI_IMG at $AMI_MNT..."
	mount -o nouuid $AMI_PART_PATH $AMI_MNT
	

	# Make our chroot directory hierarchy
	mkdir -p $AMI_MNT/{dev,etc,proc,sys,var/{cache,log,lock,lib/rpm}}
    rm -rf $AMI_MNT/var/{run,lock}
    mkdir ../run
    ln -sf $AMI_MNT/var/run ../run
    ln -sf $AMI_MNT/var/lock ../run/lock

	# Create our special devices
	mknod -m 600 $AMI_MNT/dev/console c 5 1
	mknod -m 600 $AMI_MNT/dev/initctl p
	mknod -m 666 $AMI_MNT/dev/full c 1 7
	mknod -m 666 $AMI_MNT/dev/null c 1 3
	mknod -m 666 $AMI_MNT/dev/ptmx c 5 2
	mknod -m 666 $AMI_MNT/dev/random c 1 8
	mknod -m 666 $AMI_MNT/dev/tty c 5 0
	mknod -m 666 $AMI_MNT/dev/tty0 c 4 0
	mknod -m 666 $AMI_MNT/dev/urandom c 1 9
	mknod -m 666 $AMI_MNT/dev/zero c 1 5
	ln -s null $AMI_MNT/dev/X0R

	# Bind mount /dev and /proc from our builder machine
	mount -o bind /dev $AMI_MNT/dev
	mount -o bind /dev/pts $AMI_MNT/dev/pts
	mount -o bind /dev/shm $AMI_MNT/dev/shm
	mount -o bind /proc $AMI_MNT/proc
	mount -o bind /sys $AMI_MNT/sys
}


# Install packages into AMI via yum
install_packages() {

	output "Installing packages into $AMI_MNT..."
	# Create our YUM config
	YUM_CONF=$AMI_ROOT/yum.conf
	cat > $YUM_CONF <<-EOT
	[main]
	reposdir=
	plugins=0

	[base]
	name=CentOS-7 - Base
	mirrorlist=http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=os
	#baseurl=http://mirror.centos.org/centos/7/os/x86_64/
	gpgcheck=1
	gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-7

	#released updates
	[updates]
	name=CentOS-7 - Updates
	mirrorlist=http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=updates
	#baseurl=http://mirror.centos.org/centos/7/updates/x86_64/
	gpgcheck=1
	gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-7

	#additional packages that may be useful
	[extras]
	name=CentOS-7 - Extras
	mirrorlist=http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=extras
	#baseurl=http://mirror.centos.org/centos/7/extras/x86_64/
	gpgcheck=1
	gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-7

	#additional packages that extend functionality of existing packages
	[centosplus]
	name=CentOS-7 - Plus
	mirrorlist=http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=centosplus
	#baseurl=http://mirror.centos.org/centos/7/centosplus/x86_64/
	gpgcheck=1
	enabled=0
	gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-7

	#contrib - packages by Centos Users
	[contrib]
	name=CentOS-7 - Contrib
	mirrorlist=http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=contrib
	#baseurl=http://mirror.centos.org/centos/7/contrib/x86_64/
	gpgcheck=1
	enabled=0
	gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-7

	[epel]
	name=Extra Packages for Enterprise Linux 7 - \$basearch
	#baseurl=http://download.fedoraproject.org/pub/epel/7/\$basearch
	mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=\$basearch
	failovermethod=priority
	enabled=1
	gpgcheck=0
	gpgkey=http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7

	[epel-debuginfo]
	name=Extra Packages for Enterprise Linux 7 - \$basearch - Debug
	#baseurl=http://download.fedoraproject.org/pub/epel/7/\$basearch/debug
	mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-debug-7&arch=\$basearch
	failovermethod=priority
	enabled=0
	gpgkey=http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7
	gpgcheck=1

	[epel-source]
	name=Extra Packages for Enterprise Linux 7 - \$basearch - Source
	#baseurl=http://download.fedoraproject.org/pub/epel/7/SRPMS
	mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-source-7&arch=\$basearch
	failovermethod=priority
	enabled=0
	gpgkey=http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7
	gpgcheck=1

	[elrepo]
	name=ELRepo.org Community Enterprise Linux Repository - el7
	baseurl=http://elrepo.org/linux/elrepo/el7/\$basearch/
			http://mirrors.coreix.net/elrepo/elrepo/el7/\$basearch/
			http://jur-linux.org/download/elrepo/elrepo/el7/\$basearch/
			http://repos.lax-noc.com/elrepo/elrepo/el7/\$basearch/
			http://mirror.ventraip.net.au/elrepo/elrepo/el7/\$basearch/
	mirrorlist=http://mirrors.elrepo.org/mirrors-elrepo.el7
	enabled=0
	gpgcheck=1
	gpgkey=https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

	[elrepo-kernel]
	name=ELRepo.org Community Enterprise Linux Kernel Repository - el7
	baseurl=http://elrepo.org/linux/kernel/el7/\$basearch/
			http://mirrors.coreix.net/elrepo/kernel/el7/\$basearch/
			http://jur-linux.org/download/elrepo/kernel/el7/\$basearch/
			http://repos.lax-noc.com/elrepo/kernel/el7/\$basearch/
			http://mirror.ventraip.net.au/elrepo/kernel/el7/\$basearch/
	mirrorlist=http://mirrors.elrepo.org/mirrors-elrepo-kernel.el7
	enabled=0
	gpgcheck=1
	gpgkey=https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

	[zscaler]
	name=Zscaler Private Access Repository
	baseurl=https://yum.private.zscaler.com/yum/el7
	enabled=1
	gpgcheck=1
	gpgkey=https://yum.private.zscaler.com/gpg
	EOT

	# Install base pacakges
	yum --config=$YUM_CONF --installroot=$AMI_MNT --quiet --assumeyes groupinstall base
	[[ -f $AMI_MNT/bin/bash ]] || fatal "Failed to install base packages into $AMI_MNT"

	# Install additional packages that we are definitely going to want
	yum --config=$YUM_CONF --installroot=$AMI_MNT --assumeyes install \
        psmisc grub2 dhclient chrony e2fsprogs sudo kernel-ml \
		openssh-clients vim-minimal yum-plugin-fastestmirror sysstat \
		epel-release python3 python-setuptools gcc make rsyslog microcode_ctl \
		gnupg2 bzip2 nc cloud-utils-growpart cloud-init openssh-server jq zpa-connector

	# Remove unnecessary RPMS
	yum --config=$YUM_CONF --installroot=$AMI_MNT --assumeyes erase \
		plymouth plymouth-scripts plymouth-core-libs firewalld xinetd cronie-anacron postfix portmap

	# Enable our required services
	chroot $AMI_MNT /bin/systemctl -q enable rsyslog chronyd sshd cloud-init cloud-init-local \
		cloud-config cloud-final psacct

	# Install AWS Tools
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "$AMI_MNT/tmp/awscli-exe-linux-x86_64.zip"
	unzip $AMI_MNT/tmp/awscli-exe-linux-x86_64.zip -d $AMI_MNT/tmp
	chroot $AMI_MNT /tmp/aws/install -i /usr/local/aws -b /usr/local/bin

	#install Python modules - requires the ability to resolve & download modules
	cp /etc/resolv.conf $AMI_MNT/etc
	chroot $AMI_MNT /bin/pip3 install boto3
	chroot $AMI_MNT /bin/pip3 install requests	
	rm -f $AMI_MNT/{etc/resolv.conf,root/.bash_history}

	rm -rf $AMI_MNT/tmp/*
	
	# Create our default bashrc files
	cat > $AMI_MNT/root/.bashrc <<-EOT
	alias rm='rm -i' cp='cp -i' mv='mv -i'		   
	[ -f /etc/bashrc ] && . /etc/bashrc					   
	EOT
	cp $AMI_MNT/root/.bashrc $AMI_MNT/root/.bash_profile

}


# Create the AMI's fstab
make_fstab() {
	output "Creating fstab..."
	cat > $AMI_MNT/etc/fstab <<-EOT
	LABEL=root /         xfs    defaults,relatime  1 1
	tmpfs   /dev/shm  tmpfs   defaults           0 0
	devpts  /dev/pts  devpts  gid=5,mode=620     0 0
	sysfs   /sys      sysfs   defaults           0 0
	proc    /proc     proc    defaults           0 0
	EOT
}


# Create our eth0 ifcfg script and our SSHD config
setup_network() {
	output "Setting up network..."

	# Create our DHCP-enabled eth0 config
	cat > $AMI_MNT/etc/sysconfig/network-scripts/ifcfg-eth0 <<-EOT
	DEVICE=eth0
	BOOTPROTO=dhcp
	ONBOOT=yes
	TYPE=Ethernet
	USERCTL=yes
	PEERDNS=yes
	IPV6INIT=no
	PERSISTENT_DHCLIENT=yes
	EOT

	cat > $AMI_MNT/etc/sysconfig/network <<-EOT
	NETWORKING=yes
	NOZEROCONF=yes
	EOT

	cat > $AMI_MNT/etc/sysctl.d/99-sysctl.conf <<-EOT
	net.ipv6.conf.all.disable_ipv6 = 1
	net.ipv6.conf.default.disable_ipv6 = 1
	net.ipv4.ip_local_port_range = 1024 65000
	EOT

	# Amend our SSHD config
	cat >> $AMI_MNT/etc/ssh/sshd_config <<-EOT
	PasswordAuthentication no
	UseDNS no
	PermitRootLogin without-password
	EOT

	cat motd > $AMI_MNT/etc/motd
	chroot $AMI_MNT chkconfig network on
}

setup_scripts() {
	output "Setting up ZPA Scripts..."

	cat > $AMI_MNT/etc/logrotate.conf <<-EOT
	# see "man logrotate" for details
	# rotate log files daily
	daily

	# keep 4 weeks worth of backlogs
	rotate 7

	# create new (empty) log files after rotating old ones
	create

	# use date as a suffix of the rotated file
	dateext

	# uncomment this if you want your log files compressed
	compress

	# RPM packages drop log rotation information into this directory
	include /etc/logrotate.d

	# no packages own wtmp and btmp -- we'll rotate them here
	/var/log/wtmp {
	    monthly
	    create 0664 root utmp
		minsize 1M
	    rotate 1
	}

	/var/log/btmp {
	    missingok
	    monthly
	    create 0600 root utmp
	    rotate 1
	}

	# system-specific logs may be also be configured here.
	EOT



	cat > $AMI_MNT/opt/zscaler/bin/limits.sh << END_OF_SCRIPT
#!/usr/bin/bash

#Increase Source Port Range
sysctl -w net.ipv4.ip_local_port_range="1024 65000"

#Persist Source Port Range after reboot
#Disable IPv6 Entirely
cat > /etc/sysctl.d/99-sysctl.conf <<-EOT
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.ip_local_port_range = 1024 65000
EOT


#Use Static IP/DNS Configuration.  
#Ensure 2 DNS Servers are configured.
#DNS Search Suffixes are NOT required in Connectors /etc/resolv.conf
#Ensure DNS server Rotation
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 <<-EOT
DEVICE=eth0
BOOTPROTO=none
ONBOOT=yes
TYPE=Ethernet
USERCTL=yes
IPADDR=
PREFIX=
GATEWAY=
DNS1=
DNS2=
DEFROUTE=yes
IPV6INIT=no
EOT
systemctl restart network

echo "options rotate timeout:1 retries:1" >> /etc/resolv.conf

#Unset Debug Flags (Obviously remove this if debugging is required from Zscaler Support/Engineering)
curl http://localhost:9000/debug/fohh?value=0
curl http://localhost:9000/debug/wally?value=0
curl http://localhost:9000/debug/zpath_lib?value=0
curl http://localhost:9000/debug/zpn?value=0
curl http://localhost:9000/debug/assistant?value=0
curl http://localhost:9000/debug/zhealth?value=0

#Manage size of log files and log rotation
journalctl --vacuum-size=1G
cat > /etc/logrotate.conf <<-EOT
# see "man logrotate" for details
# rotate log files daily
daily

# keep 4 weeks worth of backlogs
rotate 7

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
compress

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we'll rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
	minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
END_OF_SCRIPT
	chmod 700 $AMI_MNT/opt/zscaler/bin/limits.sh

	cat > $AMI_MNT/opt/zscaler/bin/provision.sh << "END_OF_SCRIPT"
#!/usr/bin/bash
systemctl stop zpa-connector

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
END_OF_SCRIPT
	chmod 700 $AMI_MNT/opt/zscaler/bin/provision.sh

	cat > $AMI_MNT/opt/zscaler/bin/deprovision.sh << "END_OF_SCRIPT"
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
END_OF_SCRIPT
	chmod 700 $AMI_MNT/opt/zscaler/bin/deprovision.sh

	cat > $AMI_MNT/opt/zscaler/bin/installzws.py << "END_OF_SCRIPT"
#!/usr/bin/python3
#
# Copyright 2021 Zscaler - Mark Ryan
# SPDX-License-Identifier: Apache-2.0
#

import requests, os, subprocess, boto3, tempfile, base64
from edgeutils import ApiSession

#Get AWS Environment
region=requests.get("http://169.254.169.254/latest/meta-data/placement/region").text
session = boto3.session.Session()
ssm=session.client('ssm',region_name=region)

#Retrieve ZWS Parameters from SSM
Key=ssm.get_parameter(Name='ZWS-Key',WithDecryption=True)['Parameter']['Value']
Cert=ssm.get_parameter(Name='ZWS-Cert',WithDecryption=True)['Parameter']['Value']
ClientID=ssm.get_parameter(Name='ZWS-ClientID',WithDecryption=True)['Parameter']['Value']
ClientSecret=ssm.get_parameter(Name='ZWS-ClientSecret',WithDecryption=True)['Parameter']['Value']
SiteID=ssm.get_parameter(Name='ZWS-SiteID',WithDecryption=True)['Parameter']['Value']
URLRoot=ssm.get_parameter(Name='ZWS-URLRoot',WithDecryption=True)['Parameter']['Value']

#Write certificate to disk temporarily - required for requests.get to function
cdisk = tempfile.NamedTemporaryFile(delete=False)
cdisk.write(base64.b64decode(Cert))
cdisk.close()
kdisk = tempfile.NamedTemporaryFile(delete=False)
kdisk.write(base64.b64decode(Key))
kdisk.close()
config={'url_root':"HTTPS://"+URLRoot, 'site_id': SiteID, 'username': ClientID, 'password': ClientSecret, 'cert_file': cdisk.name, 'key_file': kdisk.name}

#Create API Session
api = ApiSession(config)

#Query ZWS API for Installers - Download RHEL Latest Version
installers = api.get('installers')
for installer in installers:
    if installer['distroName']=='RHEL':
        params="x-auth-token="+requests.utils.quote(installer['authToken'])
        uri=installer['uri']
        fileName=installer['fileName']
        download=requests.get(uri,params=params)
        if download.status_code == 200:
            with open("/tmp/"+fileName, 'wb') as out_file:
                out_file.write(download.content)
        break

os.unlink(cdisk.name)
os.unlink(kdisk.name)

#install RPM and set SiteID
process=subprocess.run(['yum','-y','--nogpgcheck','install','/tmp/'+fileName])
process=subprocess.run(['/opt/edgewise/bin/edgewise_setup','--set-site-id',SiteID])
END_OF_SCRIPT
	chmod 700 $AMI_MNT/opt/zscaler/bin/installzws.py

	curl https://raw.githubusercontent.com/EdgewiseNetworks/api-examples/master/v1/python/edgeutils.py -o $AMI_MNT/opt/zscaler/bin/edgeutils.py
	chmod 700 $AMI_MNT/opt/zscaler/bin/edgeutils.py

	cat > $AMI_MNT/opt/zscaler/bin/diagnostics.sh << "END_OF_SCRIPT"
#!/usr/bin/bash
#scp zpa-diag.sh connector.domain.com:/tmp
#ssh -t connector.domain.com '/tmp/zpa-diag.sh'
#scp 'connector.domain.com:/tmp/zpa-diag*.tar.gz' ./
#Some commands need ROOT - run this script as root, or sudo ./zpa-diag.sh
#or run visudo and add the following line to the end of the sudoers file
#admin ALL=(ALL) NOPASSWD: /usr/sbin/lsof, /usr/sbin/ss, /usr/bin/openssl

exec 3>&2
exec 2> /dev/null
echo Creating Diagnostics Directory
mkdir /tmp/zpa-diag
#Following commands require ROOT.  Either run script as root, or edit SUDOERS as above
#If you run script as root, remove sudo commands below
CID=$(sudo openssl x509 -subject -noout -in /opt/zscaler/var/cert.pem | cut -d '=' -f 4 | cut -d '-' -f 2 | cut -d '.' -f 1)
sudo lsof -n -P > /tmp/zpa-diag/lsof-output.txt
sudo lsof -n | wc -l >/tmp/zpa-diag/lsof-opencount.txt
sudo ss -s > /tmp/zpa-diag/ss.txt

echo Connector ID = $CID 
echo $CID >> /tmp/zpa-diag/$CID
echo Collecting AWS Instance Type
curl --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-type -o /tmp/zpa-diag/instance-type
curl --connect-timeout 2 http://169.254.169.254/latest/meta-data/placement/availability-zone -o /tmp/zpa-diag/availability-zone
echo Collecting Azure Instance Type
curl --connect-timeout 2  -H metadata:true "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2017-08-01&format=text" -o /tmp/zpa-diag/azure-instance-type
curl --connect-timeout 2  -H metadata:true "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-08-01&format=text" -o /tmp/zpa-diag/azure-availabilty-zone

echo Running Openssl Checks
echo openssl speed -evp aes-256-cbc > /tmp/zpa-diag/openssl.txt
openssl speed -evp aes-256-cbc >> /tmp/zpa-diag/openssl.txt
echo >> /tmp/zpa-diag/openssl.txt
echo openssl speed aes-256-cbc >> /tmp/zpa-diag/openssl.txt
openssl speed aes-256-cbc >> /tmp/zpa-diag/openssl.txt

echo Collecting Journal
journalctl > /tmp/zpa-diag/journal.log
journalctl -u zpa-connector -S -1m | grep Mtunnels >/tmp/zpa-diag/mtunnels.txt

echo Collecting CPU/Memory Info
echo Memory Report
date >> memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo UNAME >> /tmp/zpa-diag/memory_report.txt
uname -a >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo HOSTNAME >> /tmp/zpa-diag/memory_report.txt
hostname >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo LSCPU >> /tmp/zpa-diag/memory_report.txt
lscpu >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo /PROC/CPUINFO >> /tmp/zpa-diag/memory_report.txt
cat /proc/cpuinfo >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo /PROC/MEMINFO >> /tmp/zpa-diag/memory_report.txt
cat /proc/meminfo >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo Processes >> /tmp/zpa-diag/memory_report.txt
echo "ps aux --sort=-pmem | head -5" >> /tmp/zpa-diag/memory_report.txt
ps aux --sort=-pmem | head -5 >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo "curl -s 127.0.0.1:9000/memory/status" >> /tmp/zpa-diag/memory_report.txt
curl -s 127.0.0.1:9000/memory/status >> /tmp/zpa-diag/memory_report.txt
echo >> /tmp/zpa-diag/memory_report.txt
echo "curl -s 127.0.0.1:9000/memory/argo" >> /tmp/zpa-diag/memory_report.txt
curl -s 127.0.0.1:9000/memory/argo >> /tmp/zpa-diag/memory_report.txt

echo Collecting File Descriptors
echo sysctl fs.file-max > /tmp/zpa-diag/file_descriptors.txt
sysctl fs.file-max >> /tmp/zpa-diag/file_descriptors.txt
echo >> /tmp/zpa-diag/file_descriptors.txt
echo ulimit -Hn >> /tmp/zpa-diag/file_descriptors.txt
ulimit -Hn >> /tmp/zpa-diag/file_descriptors.txt
echo >> /tmp/zpa-diag/file_descriptors.txt
echo ulimit -Sn >> /tmp/zpa-diag/file_descriptors.txt
ulimit -Sn

echo Collecting Disk Utilisation
echo DISK Utilisation >> /tmp/zpa-diag/disk_report.txt
df -h >> /tmp/zpa-diag/disk_report.txt

echo Collecting Port Range
mkdir /tmp/zpa-diag/portrange
cp /proc/sys/net/ipv4/ip_local_port_range >> /tmp/zpa-diag/portrange
cp /etc/sysctl.conf >> /tmp/zpa-diag/portrange
cp /etc/sysctl.d/* /tmp/zpa-diag/portrange
sysctl net.ipv4.ip_local_port_range >> /tmp/zpa-diag/portrange/current


echo Resolving co2br.prod.zpath.net - performing MTR
echo resolved IPs
dig co2br.prod.zpath.net | grep "IN A" | cut -f 3
for x in $(dig co2br.prod.zpath.net | grep "IN A" | cut -f 3)
do
	echo MTR to $x
	mtr -rnc5 $x > /tmp/zpa-diag/mtr-$x.txt
done
cp /etc/resolv.conf /tmp/zpa-diag
cp /etc/hosts /tmp/zpa-diag

echo Collecting ZPA Statistics
curl '127.0.0.1:9000/debug'  >> /tmp/zpa-diag/connector_debug_state.txt
curl '127.0.0.1:9000/assistant/dns/state/dump' >> /tmp/zpa-diag/connector_dns_state_dump.txt
curl '127.0.0.1:9000/assistant/app/dump/state_summary' >> /tmp/zpa-diag/connector_app_state_summary.txt
curl '127.0.0.1:9000/assistant/data/mtunnel/dump/stats' >> /tmp/zpa-diag/connector_mtunnel_stats.txt
ls -lR /opt/zscaler/ >> /tmp/zpa-diag/dir.txt
cp /opt/zscaler/var/version /tmp/zpa-diag
cp /opt/zscaler/var/updater.version /tmp/zpa-diag
uptime >> /tmp/zpa-diag/uptime.txt



tar -zcvf /tmp/zpa-diag-$CID.tar.gz /tmp/zpa-diag/*
rm -rf /tmp/zpa-diag
END_OF_SCRIPT
	chmod 700 $AMI_MNT/opt/zscaler/bin/diagnostics.sh

	cat motd > $AMI_MNT/etc/motd
	chroot $AMI_MNT chkconfig network on
}

harden_image() {
	echo "install usb-storage /bin/false" > $AMI_MNT/etc/modprobe.d/usb-storage.conf
	hroot $AMI_MNT authconfig --passalgo=sha512 —update
	echo "NOZEROCONF=yes" >> $AMI_MNT/etc/sysconfig/network
	echo "options ipv6 disable=1" >> $AMI_MNT/etc/modprobe.d/disabled.conf
	cat >> $AMI_MNT/etc/sysconfig/network <<-EOT
	NETWORKING_IPV6=no
	IPV6INIT=no
	EOT
	cat >> $AMI_MNT/etc/netconfig<<-EOT
	#
	# The network configuration file. This file is currently only used in
	# conjunction with the TI-RPC code in the libtirpc library.
	#
	# Entries consist of:
	#
	#       <network_id> <semantics> <flags> <protofamily> <protoname> \
	#               <device> <nametoaddr_libs>
	#
	# The <device> and <nametoaddr_libs> fields are always empty in this
	# implementation.
	#
	udp        tpi_clts      v     inet     udp     -       -
	tcp        tpi_cots_ord  v     inet     tcp     -       -
	udp6       tpi_clts      v     inet6    udp     -       -
	tcp6       tpi_cots_ord  v     inet6    tcp     -       -
	rawip      tpi_raw       -     inet      -      -       -
	local      tpi_cots_ord  -     loopback  -      -       -
	unix       tpi_cots_ord  -     loopback  -      -       -
	EOT
	echo "tty1" > $AMI_MNT/etc/securetty
	chmod 700 $AMI_MNT/root
	perl -npe 's/umask\s+0\d2/umask 077/g' -i $AMI_MNT/etc/bashrc
	perl -npe 's/umask\s+0\d2/umask 077/g' -i $AMI_MNT/etc/csh.cshrc

	touch $AMI_MNT/etc/cron.allow
	chmod 600 $AMI_MNT/etc/cron.allow
	awk -F: '{print $1}' $AMI_MNT/etc/passwd | grep -v root > $AMI_MNT/etc/cron.deny
	touch $AMI_MNT/etc/at.allow
	chmod 600 $AMI_MNT/etc/at.allow
	awk -F: '{print $1}' $AMI_MNT/etc/passwd | grep -v root > $AMI_MNT/etc/at.deny
	echo "ALL:ALL" >> $AMI_MNT/etc/hosts.deny
	echo "sshd:ALL" >> $AMI_MNT/etc/hosts.allow
	echo "install dccp /bin/false" > $AMI_MNT/etc/modprobe.d/dccp.conf
	echo "install sctp /bin/false" > $AMI_MNT/etc/modprobe.d/sctp.conf
	echo "install rds /bin/false" > $AMI_MNT/etc/modprobe.d/rds.conf
	echo "install tipc /bin/false" > $AMI_MNT/etc/modprobe.d/tipc.conf

	# Disable unnecessary services
	chroot $AMI_MNT /bin/systemctl -q disable atd smartd rdisc ntpdate netconsole mdmonitor kdump rpcbind.socket 

	echo "install cramfs /bin/false" > $AMI_MNT/etc/modprobe.d/cramfs.conf
	echo "install freevxfs /bin/false" > $AMI_MNT/etc/modprobe.d/freevxfs.conf
	echo "install jffs2 /bin/false" > $AMI_MNT/etc/modprobe.d/jffs2.conf
	echo "install hfs /bin/false" > $AMI_MNT/etc/modprobe.d/hfs.conf
	echo "install hfsplus /bin/false" > $AMI_MNT/etc/modprobe.d/hfsplus.conf
	echo "install squashfs /bin/false" > $AMI_MNT/etc/modprobe.d/squashfs.conf
	echo "install udf /bin/false" > $AMI_MNT/etc/modprobe.d/udf.conf

	echo "* hard core 0" > $AMI_MNT/etc/security/limits.conf
	chroot $AMI_MNT /usr/sbin/sysctl -w fs.suid_dumpable=0
	echo "Protocol 2" >> $AMI_MNT/etc/ssh/sshd_config
	echo "IgnoreRhosts yes" >> $AMI_MNT/etc/ssh/sshd_config
	echo "HostbasedAuthentication no" >> $AMI_MNT/etc/ssh/sshd_config
	echo "PermitUserEnvironment no" >> $AMI_MNT/etc/ssh/sshd_config
	echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> $AMI_MNT/etc/ssh/sshd_config

	chroot $AMI_MNT useradd admin -G wheel -p '$1$UjBLbxry$tO4IFGCsTTABGLCx75jt9.'
	
	cat >> $AMI_MNT/etc/rc.local<<-EOT
	if [ ! -d /home/admin/.ssh ] ; then
			mkdir -p /home/admin/.ssh
			chmod 700 /home/admin/.ssh
	fi
	# Fetch public key using HTTP
	curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key > /tmp/my-key
	cat /tmp/my-key >> /home/admin/.ssh/authorized_keys
	chmod 600 /home/admin/.ssh/authorized_keys
	chown admin:admin -R /home/admin/.ssh
	rm /tmp/my-key
	EOT
	chmod +x $AMI_MNT/etc/rc.d/rc.local
	chroot $AMI_MNT systemctl enable rc-local
	chown -r admin:admin $AMI_MNT/home/admin
	chroot $AMI_MNT userdel -rf centos
	sed -i 's/centos/admin/g' $AMI_MNT/root/.ssh/authorized_keys

}

# Create the grub config
install_grub() {
	
	AMI_BOOT_PATH=$AMI_MNT/boot
	AMI_KERNEL_VER=$(ls $AMI_BOOT_PATH | egrep -o '4\..*' | head -1)
	output "Installing GRUB2..."
	cat > $AMI_MNT/etc/default/grub <<-EOT
	GRUB_TIMEOUT=1
	GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
	GRUB_DEFAULT=saved
	GRUB_DISABLE_SUBMENU=true
	GRUB_TERMINAL="serial console"
	GRUB_SERIAL_COMMAND="serial --speed=115200"
	GRUB_CMDLINE_LINUX="console=ttyS0,115200 console=tty0 vconsole.font=latarcyrheb-sun16 crashkernel=auto vconsole.keymap=us plymouth.enable=0 net.ifnames=0 biosdevname=0"

## rd.md.uuid=<UUID you’ve got out of mdadm --detail-dev-md2>

	GRUB_DISABLE_RECOVERY="true"
	EOT
	echo 'RUN_FIRSTBOOT=NO' > $AMI_MNT/etc/sysconfig/firstboot
	chroot $AMI_MNT grub2-mkconfig -o /boot/grub2/grub.cfg
##
	chroot $AMI_MNT grub2-install $AMI_DEV_PATH

}


# Allow user to make changes to the AMI outside of the normal build process
enter_shell() {
	output "Entering AMI chroot; customize as needed.  Enter 'exit' to finish build."
	cp /etc/resolv.conf $AMI_MNT/etc
	PS1="[${AMI_NAME}-chroot \W]# " chroot $AMI_MNT &> /dev/tty
	rm -f $AMI_MNT/{etc/resolv.conf,root/.bash_history}

}


# Unmount all of the mounted devices
unmount_all() {
	output "Unmounting"
	umount -ldf $AMI_MNT/{dev/pts,dev/shm,dev,proc,sys,}
	sync
	grep -q "^[^ ]\+ $AMI_MNT" /proc/mounts && \
		fatal "Failed to unmount all devices mounted under $AMI_MNT!"

	# Also undefine our hvm devices if they are currently set up with this image file
	losetup | grep -q $AMI_IMG && undefine_hvm_dev
	aws ec2 detach-volume --volume-id $VID --instance-id $IID --device /dev/sdf
	sleep 30s
}


# Remove the dm volume and loop dev for an HVM image file
undefine_hvm_dev() {
	kpartx -d $AMI_DEV_PATH  || fatal "Unable remove partition map for $AMI_DEV_PATH"
	sync; udevadm settle
	dmsetup remove $AMI_DEV  || fatal "Unable to remove devmapper volume for $AMI_DEV"
	sync; udevadm settle
	OLD_LOOPS=$(losetup -j $AMI_IMG | sed 's#^/dev/loop\([0-9]\+\).*#loop\1#' | paste -d' ' - -)
	[[ -n $OLD_LOOPS ]] && losetup -d $OLD_LOOPS
	losetup -D
	sleep 1; sync; udevadm settle

}



snapshot_volume() {

	SID=$(aws ec2 create-snapshot --volume-id $VID --description "ZPA Connector" | grep SnapshotId | cut -d \" -f4)
	output "Created Snapshot $SID"
	output "sleeping 300s for snapshot to complete"
	sleep 300s
	output "deleting volume"
	aws ec2 delete-volume --volume-id $VID
}

register_snapshot() {
	output "aws ec2 register-image --root-device-name /dev/sda1 --block-device-mappings "[{\"DeviceName\": \"/dev/sda1\",\"Ebs\":{\"DeleteOnTermination\":true,\"SnapshotId\":\"$SID\",\"VolumeType\":\"gp2\"}}]" --ena-support --name $AMI_NAME --region $REGION --architecture x86_64 --virtualization-type hvm"
	AID=$(aws ec2 register-image --root-device-name /dev/sda1 --block-device-mappings "[{\"DeviceName\": \"/dev/sda1\",\"Ebs\":{\"DeleteOnTermination\":true,\"SnapshotId\":\"$SID\",\"VolumeType\":\"gp2\"}}]" --ena-support --name $AMI_NAME --region $REGION --architecture x86_64 --virtualization-type hvm | grep ImageId | cut -d \" -f4) 
	output "Registered new AMI as $AID"	

}

launch_instance() {
	#Launch the instance - necessary for exporting the AMI for VMWare, Microsoft, Citrix
	#update IAM-INSTANCE-PROFILE with valid ARN - access to SSM
	LIID=$(aws ec2 run-instances --image-id $AID --instance-type t2.micro --region $REGION --iam-instance-profile Arn="instance-profile/KMS_SECRET" --key-name id_rsa | grep InstanceId | cut -d \" -f4) 
	output "Launched AMI as $LIID - waiting 2 Mins"
	sleep 2m

}

## Utility functions #######################################################


# Print a message and exit
quit() {
	output "$1"
	exit 1
}


# Print a fatal message and exit
fatal() {
	quit "FATAL: $1"
}


# Perform our initial setup routines
do_setup() {

	$CFG_FILE  || get_config_opts
	install_setup_rpms
	setup_aws
	sanity_check

	# Add /usr/local/bin to our path if it doesn't exist there
	[[ ":$PATH:" != *":/usr/local/bin"* ]] && export PATH=$PATH:/usr/local/bin

	output "All build requirements satisfied."
}


# Read config opts and save them to disk
get_config_opts() {

	source $CFG_FILE

	#get_input "Path to local build folder (i.e. /root)" "BUILD_ROOT"
	#get_input "AWS User ID #" "AWS_USER"
	#get_input "S3 Bucket Name" "S3_ROOT"
	#get_input "S3 folder" "S3_DIR"
	#get_input "S3 bucket region (i.e. us-west-2)" "S3_REGION"
	#get_input "AWS R/W access key" "AWS_ACCESS"
	#get_input "AWS R/W secret key" "AWS_SECRET"

	# Create our AWS config file
	mkdir -p ~/.aws
	chmod 700 ~/.aws
	cat > $HOME/.aws/config <<-EOT
	[default]
	output = json
	region = $S3_REGION
	aws_access_key_id = $AWS_ACCESS
	aws_secret_access_key = $AWS_SECRET
	EOT

	# Write our config options to a file for subsequent runs
	rm -f $CFG_FILE
	touch $CFG_FILE
	chmod 600 $CFG_FILE
	for f in BUILD_ROOT AWS_USER S3_ROOT S3_DIR S3_REGION AWS_ACCESS AWS_SECRET; do
		eval echo $f=\"\$$f\" >> $CFG_FILE
	done

}


# Read a variable from the user
get_input()
{
	# Read into a placeholder variable
	ph=
	eval cv=\$${2}
	while [[ -z $ph ]]; do
		printf "%-45.45s : " "$1" &> /dev/tty
		read -e -i "$cv" ph &> /dev/tty
	done

	# Assign placeholder to passed variable name
	eval ${2}=\"$ph\"
}


# Present user with a yes/no question, quit if answer is no
yesno() {
	read -p "${1}? y/[n] " answer &> /dev/tty
	[[ $answer == "y" ]] || quit "Exiting"
}


output() {
	echo $* > /dev/tty
}


# Sanity check what we can
sanity_check() {

	AMI_S3_DIR=$S3_ROOT/$S3_DIR/$AMI_NAME

	# Check S3 access and file existence
	aws s3 ls s3://$S3_ROOT/$S3_DIR &> /dev/null
	[[ $? -gt 1 ]] && fatal "S3 bucket doesn't exist or isn't readable!"
	[[ -n $(aws s3 ls s3://$AMI_S3_DIR) ]] && \
		fatal "AMI S3 path ($AMI_S3_DIR) already exists;  Refusing to overwrite it"

}


# Install RPMs required by setup
install_setup_rpms() {

	RPM_LIST=/tmp/rpmlist.txt
	
	# dump rpm list to disk
	rpm -qa > $RPM_LIST
	
	# Iterate over required rpms and install missing ones
	TO_INSTALL=
	for rpm in "${REQUIRED_RPMS[@]}"; do
		if ! grep -q "${rpm}-[0-9]" $RPM_LIST; then
			TO_INSTALL="$rpm $TO_INSTALL"
		fi
	done

	if [[ -n $TO_INSTALL ]]; then
		output "Installing build requirements: $TO_INSTALL..."
		yum -y install $TO_INSTALL
	fi
}


# Set up our various EC2/S3 bits and bobs
setup_aws() {

	# ec2-ami-tools
	if [[ ! -f /usr/local/bin/ec2-bundle-image ]]; then
		output "Installing EC2 AMI tools..."
		rpm -ivh http://s3.amazonaws.com/ec2-downloads/ec2-ami-tools-1.5.6.noarch.rpm
	fi

	# PIP (needed to install aws cli)
	if [[ ! -f /bin/pip ]]; then
		output "Installing PIP..."
		easy_install pip
	fi
	if [[ ! -f /bin/aws ]]; then
		output "Installing aws-cli"
		pip install awscli
	fi

	
}

# Main code #################################################################


# Blackhole stdout of all commands unless debug mode requested
[[ "$3" != "debug" ]] && exec &> /dev/null
DM=$(date +%d%m%y-%H%M)
output "$DM"
case "$1" in
	reconfig)
		get_config_opts
		;;
	*)
		AMI_NAME=ZPACONNECTOR$DM
		output "$AMI_NAME"
		AMI_TYPE=hvm
		do_setup
		build_ami
		;;
	help)
		quit "Usage: $0 <reconfig | ZPA > [debug]"
esac

# vim: tabstop=4 shiftwidth=4 expandtab
