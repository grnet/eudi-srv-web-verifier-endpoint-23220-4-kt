#!/bin/bash

if [ ! -d "issuer-iaca-certs" ]; then
    echo "Missing IACA certificates directory: issuer-iaca-certs"
    exit
fi

for file in issuer-iaca-certs/*;
do
    keytool -importcert -noprompt -keystore snf-895798-trusted-issuers.jks -alias $file -file $file -storetype jks -storepass blue-grass-Government3
done
