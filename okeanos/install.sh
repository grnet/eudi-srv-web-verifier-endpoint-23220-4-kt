#!/bin/bash

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
	echo "This installation script works only on (a subset of) Linux-based systems (tested on Ubuntu). Exiting now."
	exit 1
fi

sudo apt-get update
sudo apt-get install openjdk-21-jdk-headless gradle haproxy

openssl ecparam -out ec_private_key.pem -name prime256v1 -genkey
openssl req -new -key ec_private_key.pem -x509 -nodes -days 365 -subj "/CN=snf-895798.vm.okeanos.grnet.gr" -out grnet_cert.pem
cat grnet_cert.pem ec_private_key.pem >> grnet_cert_key.pem
sudo cp grnet_cert_key.pem /etc/ssl/certs/

sudo cp haproxy.cfg /etc/haproxy/
sudo service haproxy restart
