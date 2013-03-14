conf.bash
========================

- most important variable is "CASBJ", which is subject of the CA
- files are creaed under "files" tree.

ca.cnf
========================

- openssl configuration for CA
- files are stored under "files" of the current working directory. 

::

    [ CA_default ]

    dir             = ./files/ca/db         # Where everything is kept

cagen.bash
========================

- provide CA 
- CA files are created under "files/ca" tree


certgen.bash
========================

- give CNAME list to ./certgen.bash
    
    ::

        ./certgen hoge.com www.hoge.com trac.hoge.com

- The first CNAME is the primary name.
- file are created under "files/san/{{primary name}}/ tree.


Sample
=======

CA
----

::

    (hoge)hdknr@wzy:~/cert$ ./cagen.bash 

    >>>>>> 1. CA Private Key
    Generating RSA private key, 4096 bit long modulus
    ........................................++
    ...............................................................++
    e is 65537 (0x10001)
    writing RSA key
    >>>>>> 2. CA CSR
    >>>>>> 3. CA Self-Signed CRT
    Using configuration from ca.cnf
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 0 (0x0)
            Validity
                Not Before: Mar  6 22:59:03 2013 GMT
                Not After : Mar  4 22:59:03 2023 GMT
            Subject:
                countryName               = JP
                stateOrProvinceName       = Tokyo
                organizationName          = Lafoglia Inc
                organizationalUnitName    = Lafoglia
                commonName                = lafoglia.jp
            X509v3 extensions:
                X509v3 Basic Constraints: 
                    CA:TRUE
                Netscape Comment: 
                    OpenSSL Generated Certificate
                X509v3 Subject Key Identifier: 
                    ED:10:F4:47:F0:1D:EA:C6:17:D6:F2:F1:EA:24:EA:E5:67:D1:1F:E5
                X509v3 Authority Key Identifier: 
                    keyid:ED:10:F4:47:F0:1D:EA:C6:17:D6:F2:F1:EA:24:EA:E5:67:D1:1F:E5
    
    Certificate is to be certified until Mar  4 22:59:03 2023 GMT (3650 days)
    Sign the certificate? [y/n]:y
    
    
    1 out of 1 certificate requests certified, commit? [y/n]y
    Write out database with 1 new entries
    Data Base Updated
    

harajuku-tech.org
------------------------

::

    (hoge)hdknr@wzy:~/cert$ ./san-cert.bash admin.harajuku-tech.org trac.harajuku-tech.org svn.harajuku-tech.org 

    Your CNAMEs are:admin.harajuku-tech.org trac.harajuku-tech.org svn.harajuku-tech.org
    CNAME:admin.harajuku-tech.org
    CNAME:trac.harajuku-tech.org
    CNAME:svn.harajuku-tech.org
    Primary CNAME:admin.harajuku-tech.org
    SubjectAltNames :DNS:trac.harajuku-tech.org,DNS:svn.harajuku-tech.org
    Generating a 2048 bit RSA private key
    ................+++
    ...............................+++
    writing new private key to 'files/san/admin.harajuku-tech.org/privatekey.pem'
    -----
    Using configuration from ca.cnf
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 1 (0x1)
            Validity
                Not Before: Mar  6 23:01:18 2013 GMT
                Not After : Mar  6 23:01:18 2014 GMT
            Subject:
                commonName                = admin.harajuku-tech.org
            X509v3 extensions:
                X509v3 Subject Alternative Name: 
                    DNS:trac.harajuku-tech.org, DNS:svn.harajuku-tech.org
    Certificate is to be certified until Mar  6 23:01:18 2014 GMT (365 days)
    Sign the certificate? [y/n]:y
    
    
    1 out of 1 certificate requests certified, commit? [y/n]y
    Write out database with 1 new entries
    Data Base Updated


