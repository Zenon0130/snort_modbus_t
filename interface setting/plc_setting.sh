#!/bin/bash
# Replace this with the IP address of your new snort gateway
new_gateway="10.103.152.8"
# Replace this with the name of your network interface
iface="eth0"
# Update the gateway IP in the configuration file
sed -i "s/gateway .*/gateway $new_gateway/" /etc/network/interfaces
# Restart the networking service to apply the changes
service networking restart