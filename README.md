# cloudbreak-bootstrap

Tool for bootstrapping VMs launched by Cloudbreak

curl -iX POST -u cbadmin:cbadmin -d '{"path":"/tmp/alma","servers":[{"name":"srv1","address":"192.168.100.100"},{"name":"srv2","address":"192.168.100.200"}]}' localhost:6060/cbboot/server/save
curl -iX POST -u cbadmin:cbadmin -d '{"clients":["172.21.250.94:8080","172.21.250.96:8080","172.21.250.97:8080","172.21.250.95:8080"],"path":"/tmp/alma","servers":[{"name":"srv1","address":"192.168.100.100"},{"name":"srv2","address":"192.168.100.200"}]}' localhost:6060/cbboot/server/distribute

curl -X POST -u cbadmin:cbadmin -d '{"data_dir":"/etc/cloudbreak/consul","servers":["10.0.0.3","10.0.0.4","10.0.0.5"],"targets":["10.0.0.3:5555","10.0.0.4:5555","10.0.0.5:5555","10.0.0.6:5555"]}' 172.21.250.116:5555/cbboot/consul/config/distribute |jq .
cat>/etc/dhcp/dhclient.conf<<EOF
#supersede domain-name-servers 127.0.0.1;
prepend domain-name-servers 127.0.0.1;
append domain-search "node.dc1.consul";
EOF


[Install]
WantedBy=multi-user.target

[Unit]
Description=Consul Service
After=network-online.target network.service

[Service]
Type=forking
Restart=on-failure
TimeoutSec=5min
IgnoreSIGPIPE=no
KillMode=process
GuessMainPID=no
RemainAfterExit=yes
ExecStart=/usr/sbin/consul agent -config-dir=/etc/cloudbreak/consul