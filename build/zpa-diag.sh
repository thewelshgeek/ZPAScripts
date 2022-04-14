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
