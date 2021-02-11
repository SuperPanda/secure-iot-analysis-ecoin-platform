#!/bin/bash
# Author: Andrew Briscoe (21332512)
# Date: 2015-05-20
# initially based on: https://jamielinux.com/articles/2013/08/act-as-your-own-certificate-authority/
# and then https://jamielinux.com/articles/2013/08/create-and-sign-ssl-certificates-certificate-authority/
# but then decided to generate all the certs and deploy them at once, probably need to be su
# instead of having trust chain, i just make all keys that are required for bank authorisation
# and distribute them, and then add them into the truststore of the bank
# One liner: http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
rm -rf $DIR/../bank/private 2> /dev/null
rm -rf $DIR/../bank/keystore 2> /dev/null
rm -rf $DIR/../bank/truststore 2> /dev/null
rm -rf $DIR/../collector/certs 2> /dev/null
rm -rf $DIR/../collector/truststore 2> /dev/null
rm -rf $DIR/../analyst/private 2> /dev/null
rm -rf $DIR/../analyst/truststore 2> /dev/null
mkdir -p $DIR/../bank/private
mkdir -p $DIR/../bank/keystore
mkdir -p $DIR/../bank/truststore
mkdir -p $DIR/../collector/certs
mkdir -p $DIR/../collector/truststore
mkdir -p $DIR/../analyst/private
mkdir -p $DIR/../analyst/truststore
chmod 700 $DIR/../bank/private
echo "Generating bank private key."
openssl genrsa -out $DIR/../bank/private/bank.key.pem
echo "Setting bank private key permission."
chmod 400 $DIR/../bank/private/bank.key.pem
echo "Self-signing root CA."
openssl req -new -x509 -days 3650 -key $DIR/../bank/private/bank.key.pem -sha256 -out $DIR/../bank/keystore/bank.cert.pem -subj "/C=AU/ST=WA/O=PANDASPORTAL/OU=BANK/CN=localhost"
echo "Generating collector private key."
openssl genrsa -out ../collector/certs/collector.key.pem 2048
echo "Generating analyst private key."
openssl genrsa -out ../analyst/private/analyst.key.pem 2048
echo "Generating Collector certificate signing request."
openssl req -new -key ../collector/certs/collector.key.pem -out ../collector/certs/collector.cert.csr
echo "Generating Analyst certificate signing request."
openssl req -new -key  ../analyst/private/analyst.key.pem -out ../analyst/private/analyst.cert.csr
echo "Signing collector CSR with bank root CA."
openssl x509 -req -in ../collector/certs/collector.cert.csr -CA ../bank/keystore/bank.cert.pem -CAkey ../bank/private/bank.key.pem -CAcreateserial -days 365 -out ../collector/certs/collector.cert.pem
echo "Signing analyst CSR with bank root CA."
openssl x509 -req -in ../analyst/private/analyst.cert.csr -CA ../bank/keystore/bank.cert.pem -CAkey ../bank/private/bank.key.pem -CAcreateserial -days 365 -out ../analyst/private/analyst.cert.pem
chmod 444 $DIR/../bank/keystore/bank.cert.pem
rm -rf $DIR/../collector/truststore/*
rm -rf $DIR/../analyst/truststore/*
rm -rf $DIR/../bank/truststore/*
cp $DIR/../bank/keystore/bank.cert.pem $DIR/../collector/truststore/bank.cert.pem
cp $DIR/../bank/keystore/bank.cert.pem $DIR/../analyst/truststore/bank.cert.pem
mkdir -p $DIR/../collector/certs
cat $DIR/../collector/certs/collector.cert.pem $DIR/../collector/certs/collector.key.pem > $DIR/../bank/truststore/collector.cert.pem
mkdir -p $DIR/../analyst/private
cat $DIR/../analyst/private/analyst.cert.pem $DIR/../analyst/private/analyst.key.pem > $DIR/../bank/truststore/analyst.cert.pem
