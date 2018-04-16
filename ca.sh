#!/bin/bash

set -euo pipefail


ca_build()
(

    function finish {
        # Your cleanup code here
        echo "finish"
        exit 0
    }
    trap finish EXIT

    

    local CaRoot=/root/ca
    local Imed=/root/ca/intermediate
    local ScriptDir=/root/ca-scripts

    echo_script()
    {
        while read line; do
            if [[ -z $line ]]; then continue; fi
            echo ">>>>>>"
            echo ">>>>>> $line"
            eval "$line"
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo "ERROR $rc stop processing"
                return 1
            fi
        done
    }


    uninstall()
    {
        rm -rf $CaRoot
    }

    init_ca()
    {
        mkdir $CaRoot
        cd $CaRoot
        cp $ScriptDir/openssl-ca.cnf .
        mkdir certs crl newcerts private
        chmod 700 private
        touch index.txt
        tree $CaRoot
        # echo 1000 > serial
    }

    init_intermediate()
    {
        mkdir -p $Imed
        cd $Imed
        cp $ScriptDir/openssl-intermediate.cnf .
        mkdir certs crl csr newcerts private
        chmod 700 private
        touch index.txt
        tree $CaRoot
        #echo 1000 > serial
        #echo 1000 > /root/ca/intermediate/crlnumber
    }

    make_ca_cert()
    {
        echo_script <<EOF_
openssl genrsa -out $CaRoot/private/ca.key.pem 4096 # add -aes256 for password 
chmod 400 $CaRoot/private/ca.key.pem
openssl req -batch -config $CaRoot/openssl-ca.cnf \
 -key $CaRoot/private/ca.key.pem \
 -new -x509 -days 7300 -sha256 -extensions v3_ca \
 -out $CaRoot/certs/ca.cert.pem
chmod 444 $CaRoot/certs/ca.cert.pem
openssl x509 -noout -text -in $CaRoot/certs/ca.cert.pem
EOF_
    }

    make_intermediate_cert()
    {
        echo_script <<EOF_
        echo_script <<EOF_
openssl genrsa -out $Imed/private/intermediate.key.pem 4096 # add -aes256 for password
# Create the request
openssl req -batch -config $Imed/openssl-intermediate.cnf -new -sha256 \
 -key $Imed/private/intermediate.key.pem \
 -out $Imed/csr/intermediate.csr.pem
# Sign the certificate
openssl ca -batch -config $CaRoot/openssl-ca.cnf -extensions v3_intermediate_ca \
 -create_serial \
 -days 3650 -notext -md sha256 \
 -in $Imed/csr/intermediate.csr.pem \
 -out $Imed/certs/intermediate.cert.pem
chmod 444 $Imed/certs/intermediate.cert.pem
cat $CaRoot/index.txt
# Check details
openssl x509 -noout -text \
 -in $Imed/certs/intermediate.cert.pem
# Verify chain of trust
openssl verify -CAfile $CaRoot/certs/ca.cert.pem \
 $Imed/certs/intermediate.cert.pem
EOF_

        cat $Imed/certs/intermediate.cert.pem \
            $CaRoot/certs/ca.cert.pem > $Imed/certs/ca-chain.cert.pem
        chmod 444 $Imed/certs/ca-chain.cert.pem
    }

    make_usr_cert() #arg $1: unique identifier
    {
        if [[ -z $1 ]]; then
            echo "unique identifier required"
            return 1
        fi
        local Id=$1
        echo_script <<EOF_
openssl genrsa -out $Imed/private/$Id.key.pem 2048 # -aes256 left out, no password used
chmod 400 $Imed/private/$Id.key.pem
openssl req -batch -config $Imed/openssl-intermediate.cnf \
 -subj "/CN=$Id" \
 -key $Imed/private/$Id.key.pem \
 -new -sha256 -out $Imed/csr/$Id.csr.pem

openssl ca -batch -config $Imed/openssl-intermediate.cnf \
 -create_serial \
 -extensions usr_cert -days 375 -notext -md sha256 \
 -in $Imed/csr/$Id.csr.pem \
 -out $Imed/certs/$Id.cert.pem
chmod 444 $Imed/certs/$Id.cert.pem

cat $Imed/index.txt

# Check details
openssl x509 -noout -text \
 -in $Imed/certs/$Id.cert.pem

# Verify chain of trust
openssl verify -CAfile $Imed/certs/ca-chain.cert.pem \
 $Imed/certs/$Id.cert.pem

EOF_
    }

    test()
    {
        echo_script <<EOF_
        uninstall
        init_ca
        make_ca_cert
        init_intermediate
        make_intermediate_cert
        make_usr_cert my-client
EOF_
        
    }

    ${@}

)

