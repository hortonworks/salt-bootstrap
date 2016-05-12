FROM centos:6

RUN yum install -y nc
RUN yum install -y system-config-services
RUN yum install -y epel-release
RUN yum install -y salt-master salt-minion salt-api

ENTRYPOINT nc -l 1111
