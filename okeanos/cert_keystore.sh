#!/usr/bin/env bash

# To create snf-82771.ok-kno.grnetcloud.net.p12 for signing JAR certificates in x509_san_dns
# visit https://registry.serviceproviders.eudiw.dev
# from a mobile app/emulator that has the (Android) EUDI wallet app installed.
# Proposed keystore password (requested when keytool command is issued): grnet
CERT="snf-82771.ok-kno.grnetcloud.net.p12"

keytool -importkeystore -srckeystore "${CERT}" -srcstoretype pkcs12 \
	-srcalias snf-82771.ok-kno.grnetcloud.net -destkeystore ../src/main/resources/keystore.jks \
	-deststoretype jks -destalias snf-82771.ok-kno.grnetcloud.net -deststorepass 'keystore'
