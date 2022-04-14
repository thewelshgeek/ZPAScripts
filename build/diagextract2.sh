#!/usr/bin/bash
for f in *.tar.gz ; 
do x=`echo "$f" | cut -d . -f 1`
mkdir $x ; tar -xvf $f -C $x ; mv $x/tmp/zpa-diag/* $x ;rm -rf $x/tmp ; done

for f in *.tar.gz ; do x=`echo "$f" | cut -d . -f 1` ;rm -rf $x/tmp ; done