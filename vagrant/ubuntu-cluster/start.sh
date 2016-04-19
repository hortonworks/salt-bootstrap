#!/bin/bash

export GOPATH=/home/vagrant/go
mkdir -p ${GOPATH}/src/github.com/sequenceiq/
cd ${GOPATH}/src/github.com/sequenceiq/

if [ ! \( -e "cloudbreak-bootstrap" \) ]
then
     echo "cloudbreak-bootstrap does not exsist and will be linked!"
     ln -s /cloudbreak-bootstrap cloudbreak-bootstrap
fi

echo "Fetching dependencies"
go get github.com/gorilla/mux
go get github.com/samalba/dockerclient
go get github.com/hashicorp/consul-template


export CBBOOT_JOIN_FILE=/home/vagrant/join.json

echo "Staring cloudbreak-bootstrap"
cd cloudbreak-bootstrap
cd /cloudbreak-bootstrap && ./cloudbreak-bootstrap