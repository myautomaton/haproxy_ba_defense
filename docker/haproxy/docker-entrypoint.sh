#!/bin/bash

rsyslogd
touch /var/log/haproxy-traffic.log
haproxy -f /etc/haproxy/haproxy.cfg
sleep 1s
tail -f /var/log/haproxy-traffic.log