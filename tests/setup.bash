#!/bin/bash

CNAME=www.hoge.com
CERTSDIR=certs
BASE=`pwd`
STORE=$BASE/_files/certs/$CNAME
#
if [ ! -d $STORE ] ; then
    ./cert/cagen.bash
    ./cert/certgen.bash $CNAME
fi
#
mkdir -p $CERTSDIR
ln -s $STORE/cert.pem certs/cert.pem -f
ln -s $STORE/privatekey.pem certs/server.key -f
