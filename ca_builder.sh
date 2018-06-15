#!/bin/bash

set -euo pipefail

# password files for keys created with openssl genrsa
#  $CaRoot/private/ca.key.pw   
#  $Imed/private/intermediate.key.pw
#  NOT! $Imed/private/my-client.key.pw

# "Export Password" for pkcs format cert
#  $Imed/private/my-client.client.p12.pw


ca_builder()
(
#    set -x
    local TopDir=/etc/ssl/MyOrg-CA
    local CaIdent=ca-1
    local CaRoot=$TopDir/$CaIdent
    local ImedIdent=imed-2
    local ImedRoot=$CaRoot/$ImedIdent
    local ProtoConfDir=.                   #included with this script
    local MyOrg="MyOrg"
    local SharedSubj="/C=US/ST=XXX/O=$MyOrg"
    local CaSubj="$SharedSubj/CN=$MyOrg.$CaIdent"
    local ImedSubj="$SharedSubj/CN=$MyOrg.$CaIdent.$ImedIdent"
    
    
    function finish {
        local ec=$?
        if [[ $ec -eq 0 ]]; then
            echo "finished - Success" >&2
        else
            echo "finished - Failure" >&2
        fi
        exit 0
    }
    trap finish EXIT

    
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

    rand_to_file() # $1 = file to which to save rand which is also returned
    {
        touch $1
        chmod 600 $1
        openssl rand -base64 20 > $1
        chmod 400 $1
    }

    delete_all()
    {
        rm -rf $TopDir
    }

    modify_openssl_cfg() # $1=<cfgfilepath> $2=<ident> $3=<dirpath> 
    {
        local sed_line_range='/^\[ CA_default \]$/,/^\[/'
        local sed_subs_identity="s|^identity[ ]*=.*$|identity = $2|"
        local sed_subs_dir="s|^dir[ ]*=.*$|dir = $3|"
        sed -i "$sed_line_range $sed_subs_identity" $1
        sed -i "$sed_line_range $sed_subs_dir" $1        
    }

    
    init_ca()
    {
        if [[ -d $CaRoot ]]; then
            echo "ERROR: $CaRoot already exists"
            exit 1
        fi
        mkdir -p $CaRoot
        cp $ProtoConfDir/openssl.cnf.tpl $CaRoot/openssl-ca.cnf

        modify_openssl_cfg $CaRoot/openssl-ca.cnf $CaIdent $CaRoot
        
        mkdir $CaRoot/{certs,crl,newcerts,private}
        chmod 700 $CaRoot/private
        touch $CaRoot/index.txt
        tree $CaRoot
        make_ca_cert
    }

    init_intermediate()
    {
        if [[ -d $ImedRoot ]]; then
            echo "ERROR: $ImedRoot already exists"
            exit 1
        fi
        mkdir $ImedRoot 
        cp $ProtoConfDir/openssl.cnf.tpl $ImedRoot/openssl-intermediate.cnf

        modify_openssl_cfg $ImedRoot/openssl-intermediate.cnf $ImedIdent $ImedRoot
        
        mkdir $ImedRoot/{certs,crl,newcerts,private,csr}
        chmod 700 $ImedRoot/private
        touch $ImedRoot/index.txt
        tree $ImedRoot
        make_intermediate_cert
    }

    make_ca_cert()
    {
        
        local pwfile=$CaRoot/private/$CaIdent.key.pw
        rand_to_file $pwfile
        
        echo_script <<EOF_
# key with password
openssl genrsa -out $CaRoot/private/$CaIdent.key.pem \
 -aes256 -passout file:$pwfile 4096

chmod 400 $CaRoot/private/$CaIdent.key.pem

openssl req -batch -config $CaRoot/openssl-ca.cnf \
 -subj "$CaSubj" \
 -key $CaRoot/private/$CaIdent.key.pem -passin file:$pwfile\
 -new -x509 -days 7300 -sha256 -extensions v3_ca \
 -out $CaRoot/certs/$CaIdent.cert.pem

chmod 444 $CaRoot/certs/$CaIdent.cert.pem

openssl x509 -noout -text -in $CaRoot/certs/$CaIdent.cert.pem
EOF_
    }

    make_intermediate_cert()
    {

        local pwfile=$ImedRoot/private/$ImedIdent.key.pw
        rand_to_file $pwfile
        
        echo_script <<EOF_
# key with password 
openssl genrsa -out $ImedRoot/private/$ImedIdent.key.pem \
 -aes256 -passout file:$pwfile 4096

chmod 400 $ImedRoot/private/$ImedIdent.key.pem

# Create the request
openssl req -batch -config $ImedRoot/openssl-intermediate.cnf -new -sha256 \
 -subj "$ImedSubj" \
 -key $ImedRoot/private/$ImedIdent.key.pem -passin file:$pwfile \
 -out $ImedRoot/csr/$ImedIdent.csr.pem

# Sign the certificate
openssl ca -batch -config $CaRoot/openssl-ca.cnf -extensions v3_intermediate_ca \
 -passin file:$CaRoot/private/$CaIdent.key.pw \
 -create_serial \
 -policy policy_strict \
 -days 3650 -notext -md sha256 \
 -in $ImedRoot/csr/$ImedIdent.csr.pem \
 -out $ImedRoot/certs/$ImedIdent.cert.pem
chmod 444 $ImedRoot/certs/$ImedIdent.cert.pem
cat $CaRoot/index.txt

# Check details
openssl x509 -noout -text \
 -in $ImedRoot/certs/$ImedIdent.cert.pem

# Verify chain of trust
openssl verify -CAfile $CaRoot/certs/$CaIdent.cert.pem \
 $ImedRoot/certs/$ImedIdent.cert.pem
EOF_

        cat $ImedRoot/certs/$ImedIdent.cert.pem \
            $CaRoot/certs/$CaIdent.cert.pem > $ImedRoot/certs/$CaIdent.$ImedIdent.chain.cert.pem
        chmod 444 $ImedRoot/certs/$CaIdent.$ImedIdent.chain.cert.pem
    }

    make_usr_cert() #arg $1: unique identifier
    {
        if [[ -z $1 ]]; then
            echo "unique identifier required"
            return 1
        fi
        local Id=$1


        local p12_pwfile=$ImedRoot/private/$Id.certandkey.p12.pw
        rand_to_file $p12_pwfile

        
        echo_script <<EOF_
openssl genrsa -out $ImedRoot/private/$Id.key.pem 2048 # -aes256 left out, no password used
chmod 400 $ImedRoot/private/$Id.key.pem
openssl req -batch -config $ImedRoot/openssl-intermediate.cnf \
 -subj "/CN=$CaIdent.$ImedIdent.$Id" \
 -key $ImedRoot/private/$Id.key.pem \
 -new -sha256 -out $ImedRoot/csr/$Id.csr.pem

openssl ca -batch -config $ImedRoot/openssl-intermediate.cnf \
 -passin file:$ImedRoot/private/$ImedIdent.key.pw \
 -create_serial \
 -policy policy_loose \
 -extensions usr_cert -days 375 -notext -md sha256 \
 -in $ImedRoot/csr/$Id.csr.pem \
 -out $ImedRoot/certs/$Id.cert.pem
chmod 444 $ImedRoot/certs/$Id.cert.pem

cat $ImedRoot/index.txt

# Check details
openssl x509 -noout -text \
 -in $ImedRoot/certs/$Id.cert.pem

# Verify chain of trust
openssl verify -CAfile $ImedRoot/certs/$CaIdent.$ImedIdent.chain.cert.pem \
 $ImedRoot/certs/$Id.cert.pem

# Make the pkcs12 format data (cert+key) for browser (client) use
openssl pkcs12 -export -clcerts \
 -in $ImedRoot/certs/$Id.cert.pem \
 -inkey $ImedRoot/private/$Id.key.pem \
 -passout file:$p12_pwfile \
 -out $ImedRoot/certs/$Id.certandkey.p12

EOF_
    }

    test_all()
    {
        echo_script <<EOF_
#==========================================================================
#==========================================================================
delete_all       
#==========================================================================
#==========================================================================
init_ca
#==========================================================================
#==========================================================================
init_intermediate
#==========================================================================
#==========================================================================
make_usr_cert my-client-1
#==========================================================================
tree $CaRoot
EOF_
        
    }

    make_usr_cert_after_notice() # $1 identity
    {
        echo "The client cert (e.g. to be loaded into browser) and it's password file:"
        ls -l  $ImedRoot/certs/$1.certandkey.p12
        ls -l  $ImedRoot/private/$1.certandkey.p12.pw
        echo "The chain of certs for the recipient of client cert (e.g. nginx server)"
        ls -l  $ImedRoot/certs/$CaIdent.$ImedIdent.chain.cert.pem
        echo "NOTE: You might consider storing these passwords in a pw manager and deleting the files: ($0 show_passwords to show password text values)"
        ls -l  $CaRoot/private/*.pw
        ls -l  $ImedRoot/private/*.pw       
    }

    show_passwords() 
    {
        find $CaRoot/private -name *.pw -exec ls -l {} \; -exec cat {} \;
        find $ImedRoot/private -name *.pw -exec ls -l {} \; -exec cat {} \;
    }
    show_all_passwords()
    {
        find $TopDir -name *.pw -exec ls -l {} \; -exec cat {} \;
    }
    delete_all_passwords()
    {
        find $TopDir -name *.pw -exec ls -l {} \; -exec rm -f {} \;
    }
    # find /etc/ssl/MyOrg-CA -name *.pw -exec echo {} \; -exec cat {} \;
    # find /etc/ssl/MyOrg-CA -name *.pw -exec echo {} \; -exec rm {} \;

    ca_chain_filepath()
    {
        echo "$ImedRoot/certs/$CaIdent.$ImedIdent.chain.cert.pem"
    }
    usr_cert_filepath() # $1 id
    {
        echo "$ImedRoot/certs/$1.certandkey.p12"
    }
    help()
    {
        cat <<EOF_
current top CA is $CaIdent
current intermediate CA is $ImedIdent
USAGE: ca_build <command> <args>
where <command> is one of:
  test-all
     intended for development and testing ONLY
     delete all current top/intermediate/bottom data (DANGER!!!!)
     create new top CA $CaIdent
     create new intermediate CA $ImedIdent
     create new client cert my-client-1

  init-ca-and-imed
     create new top CA $CaIdent
     create new intermediate CA $ImedIdent
     will fail if pre-existing
      
  init-imed
     create new intermediate CA $ImedIdent
     will fail if pre-existing

  make-usr-cert <usr cert identity string (alphanum, hyphen, underbar only, no whitespace)>
     create new client p12 cert
     note: identity should not be pre-existing under current top/intermediate CAs

  show-passwords
     for all undeleted passwords files under current top and intermediate CAs 
        show those file paths and file contents

  show-all-passwords
     for all undeleted passwords files under ALL top and intermediate CAs 
        show those file paths and file contents 

  ca-chain-filepath
     returns string "$(ca_chain_filepath)"

  usr-cert-filepath <usr-cert-identity-string>
     returns string "$(usr_cert_filepath '<usr-cert-identity-string>')"

EOF_
    }

    checkroot()
    {
        if ! [[ "$(whoami)" = "root" ]] ; then
            echo "WARNING: you are not root - probably only root should run ${0}"
            exit
        fi
    }
    
    if [[ ${#@} -ge 1 ]]; then
        command=$1
    else
        command="help"
    fi
    case $command in
        XXX)
            shift
            ${@} # allows calling individual functions in ca_build()
            ;;
        test-all)
            checkroot
            test_all
            ;;
        init-ca-and-imed)
            checkroot
            init_ca
            init_intermediate
            ;;
        init-imed)
            checkroot
            init_intermediate
            ;;
        make-usr-cert)
            checkroot
            make_usr_cert $2
            make_usr_cert_after_notice $2  
            ;;
        show-passwords)
            show_passwords;
            ;;
        show-all-passwords)
            checkroot
            show_all_passwords;
            ;;
        delete-all-passwords)
            checkroot
            delete_all_passwords;
            ;;
        ca-chain-filepath)
            ca_chain_filepath
            ;;
        usr-cert-filepath)
            usr_cert_filepath $2
            ;;
        *)
            help
            ;;
    esac
    
)

if ! [ "$0" = "/bin/bash" ]; then
    ca_builder ${@}
fi
