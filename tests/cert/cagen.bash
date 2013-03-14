#!/bin/bash

CONF=`dirname $0`/conf.bash

if [ ! -f $CONF ]; then
  echo "create conf.bash and configure it"
  exit
fi
source $CONF 

########################
if [  -d $CADB/newcerts ] ; then
    rm -rf $CADB
fi
mkdir -p $CADB/newcerts
touch $CADB/index.txt
echo 00  > $CADB/serial

#########################
echo ">>>>>> 1. CA Private Key"
# key with password
echo "openssl genrsa -des3 -passout pass:$PWD  -out $CAKEY.pwd 4096"
openssl genrsa -des3 -passout pass:$PWD  -out $CAKEY.pwd 4096
# key without password
echo "openssl rsa -passin pass:$PWD -in $CAKEY.pwd -out $CAKEY"
openssl rsa -passin pass:$PWD -in $CAKEY.pwd -out $CAKEY

echo ">>>>>> 2. CA CSR"
echo "openssl req -new -key $CAKEY -passin pass:$PWD -out $CACSR  -subj $CASBJ"
openssl req -new -key $CAKEY -passin pass:$PWD -out $CACSR  -subj "$CASBJ"

echo ">>>>>> 3. CA Self-Signed CRT"
echo "openssl ca -config $CACONF -passin pass:$PWD  -in $CACSR -out $CACRT -keyfile $CAKEY -selfsign -days 3650"
openssl ca -config $CACONF -passin pass:$PWD  -in $CACSR -out $CACRT -keyfile $CAKEY -selfsign -days 3650
openssl x509 -inform pem -passin pass:$PWD  -in $CACRT -out $CACRT.der -outform der
