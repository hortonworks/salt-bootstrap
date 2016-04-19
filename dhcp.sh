#!/bin/bash

cat>/etc/dhcp/dhclient.conf<<EOF
#supersede domain-name-servers 127.0.0.1;
prepend domain-name-servers 127.0.0.1;
append domain-search "node.dc1.consul";
EOF
