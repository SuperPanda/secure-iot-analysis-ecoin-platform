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
chmod 700 $DIR/../bank/private
openssl genrsa -out $DIR/../bank/private/bank.key.pem
chmod 400 $DIR/../bank/private/bank.key.pem
openssl req -new -x509 -days 3650 -key $DIR/../bank/private/bank.key.pem -sha256 -out $DIR/../bank/keystore/bank.cert.pem -subj "/C=AU/ST=WA/O=PANDASPORTAL/OU=BANK/CN=localhost"
openssl genrsa -out ../collector/certs/collector.key.pem 2048
openssl genrsa -out ../analyst/private/analyst.key.pem 2048
openssl req -new -key ../collector/certs/collector.key.pem -out ../collector/certs/collector.cert.csr
openssl req -new -key  ../analyst/private/analyst.key.pem -out ../analyst/private/analyst.cert.csr
openssl x509 -req -in ../collector/certs/collector.cert.csr -CA ../bank/keystore/bank.cert.pem -CAkey ../bank/private/bank.key.pem -CAserial serial.txt -days 365 -out ../collector/certs/collector.cert.pem
openssl x509 -req -in ../analyst/private/analyst.cert.csr -CA ../bank/keystore/bank.cert.pem -CAkey ../bank/private/bank.key.pem -CAserial serial.txt -days 365 -out ../analyst/private/analyst.cert.pem
chmod 444 $DIR/../bank/keystore/bank.cert.pem
rm $DIR/../collector/truststore/*
rm $DIR/../analyst/truststore/*
rm $DIR/../bank/truststore/*
cp $DIR/../bank/keystore/bank.cert.pem $DIR/../collector/truststore/bank.cert.pem
cp $DIR/../bank/keystore/bank.cert.pem $DIR/../analyst/truststore/bank.cert.pem
cat $DIR/../collector/certs/collector.cert.pem $DIR/../collector/certs/collector.key.pem > $DIR/../bank/truststore/collector.cert.pem
cat $DIR/../analyst/private/analyst.cert.pem $DIR/../analyst/private/analyst.key.pem > $DIR/../bank/truststore/analyst.cert.pem
