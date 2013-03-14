#!/bin/bash
CASBJ="/C=JP/ST=Tokyo/L=Shibuyaku/O=Lafoglia Inc/OU=Lafoglia/CN=lafoglia.jp"
#
PWD=hogehoge
COUNTRY=JP
#
CACONF=`dirname $0`/ca.cnf
FILES=`pwd`/_files
#
CADB=$FILES/ca/db
CABASE=$FILES/ca
CAKEY=$CABASE/ca.key
CACSR=$CABASE/ca.csr
CACRT=$CABASE/ca.crt
