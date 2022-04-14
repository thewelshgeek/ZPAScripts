for f in `find . -name "99-sysctl.conf"` ; do echo $f ; dir=`echo $f | cut -f 2 -d \/` ; if [ `grep -c net.ipv4.ip_local_port_range $f` -eq "0" ] ; then echo default; cat ./$dir/portrange/current; else echo custom; cat ./$dir/portrange/current ; fi ; done



for f in `find . -name "99-sysctl.conf"` ; do dir=`echo $f | cut -f 2 -d \/` ; if [ `grep -c net.ipv4.ip_local_port_range $f` -eq "1" ] ; then echo $dir will persist ;  else echo $dir will not persist;  fi ; done


for f in `find . -name "current"` ; do dir=`echo $f | cut -f 2 -d \/` ; cid=`echo $dir | cut -f 3 -d -` ; days=`cut -f 4 -d " " $dir/uptime.txt` ; cpus=`grep "^CPU(s)" $dir/memory_report.txt | cut -f 17 -d " "`; memory=`grep "^MemTotal" $dir/memory_report.txt |  sed 's/ //g' | cut -f 2 -d :` ; cname=`grep $cid siemens_connectors.csv | cut -f 1 -d ,` ; if [ `grep -c 1024 $f` -eq "1" ] ; then echo $cid,$cname,set,$days,$cpus,$memory >>ports.csv;  else echo $cid,$cname,unset,$days,$cpus,$memory >>ports.csv ;  fi ; done


for f in `find . -name "current"` ; do cat $f ;  fi ; done