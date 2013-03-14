#!/bin/bash
CONF=`dirname $0`/conf.bash

# 0. Setup
if [ ! -f $CONF ] ; then
  echo "Create conf.bash and configure it."
  exit
fi

source $CONF

if [ ! -d $CADB ] ; then
  echo "Run cagen.bash to create CA first."
  exit
fi

# 1. Arguments
if [ $# == 0 ] ; then
  echo "specify CNAME list or list file"
  exit
fi

# 2. CNAME list
CNS=
if [ -f $1 ] ; then
    CNS=`cat $1`
else
    CNS=$@
fi
echo "Your CNAMEs are:$CNS"

# 3. Primary CNAME and SubjectAltNames

COMMONNAME=  #
SAN=1        # bogus value to begin the loop
SANAMES=""   # sanitize

for cname in $CNS ; do
    echo "CNAME:$cname"
    if   [ "$COMMONNAME" = "" ]; then
        COMMONNAME=$cname
    elif [ "$SANAMES"   = "" ]; then
        SANAMES="DNS:$cname"
    else
        SANAMES="$SANAMES,DNS:$cname"
    fi
done
echo "Primary CNAME:$COMMONNAME"
echo "SubjectAltNames :$SANAMES"

# 4. parameters
BASE=$FILES/certs/$COMMONNAME

if [ ! -d $BASE ] ; then
    mkdir -p $BASE
fi
CONFIG=$BASE/config.txt

#
LASTUMASK=`umask`
umask 077

#################################################
# 5. Genrate configuration file

cat <<EOF > $CONFIG
# -------------- BEGIN custom openssl.cnf -----
 HOME                    = $HOME
EOF

cat <<EOF >> $CONFIG
 oid_section             = new_oids
 [ new_oids ]
 [ req ]
 default_days            = 730            # how long to certify for
 default_keyfile         = $BASE/privatekey.pem
 distinguished_name      = req_distinguished_name
 encrypt_key             = no
 string_mask = nombstr
EOF

if [ ! "$SANAMES" = "" ]; then
    echo "req_extensions = v3_req # Extensions to add to certificate request" >> $CONFIG
fi

cat <<EOF >> $CONFIG
 [ req_distinguished_name ]
 countryName             = $COUNTRY
 commonName              = Common Name (eg, YOUR name)
 commonName_default      = $COMMONNAME
 commonName_max          = 64
 [ v3_req ]
EOF

if [ ! "$SANAMES" = "" ]; then
    echo "subjectAltName=$SANAMES" >> $CONFIG
fi

echo "# -------------- END custom openssl.cnf -----" >> $CONFIG

# 6. Create Private Key and CSR 
openssl req -batch -config $CONFIG -newkey rsa:2048 -out $BASE/csr.pem

# 7. Create certificate
openssl ca -config $CACONF -in $BASE/csr.pem -passin pass:$CAPWD -cert $CACRT -keyfile $CAKEY -out $BASE/cert.pem -extensions v3_req -extfile $CONFIG
#
#echo ">>>>>> 4. Check$CN CERT"
#openssl x509 -in $CRT -text
#
