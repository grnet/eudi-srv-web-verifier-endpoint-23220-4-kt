#!/bin/bash

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
	echo "This installation script works only on (a subset of) Linux-based systems (tested on Ubuntu). Exiting now."
	exit 1
fi

sudo apt-get update
sudo apt-get install openjdk-21-jdk-headless gradle haproxy
sudo cp haproxy.cfg /etc/haproxy/
sudo service haproxy restart
