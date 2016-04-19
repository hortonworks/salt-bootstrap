#!/bin/bash

cat>/etc/systemd/system/consul.service<<EOF
[Install]
WantedBy=multi-user.target

[Unit]
Description=Consul Service
After=network-online.target network.service

[Service]
Restart=on-failure
TimeoutSec=5min
IgnoreSIGPIPE=no
KillMode=process
GuessMainPID=no
ExecStart=/usr/sbin/consul agent -config-dir=/etc/cloudbreak/consul | tee /var/log/consul.log
EOF

