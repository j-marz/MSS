#!/bin/bash

malware="$1"
malware_description="$2"

# set fqdn for sendmail
if ! echo "$(hostname -i)\t$(hostname) $(hostname).localhost" >> /etc/hosts; then 
	echo "updating /etc/hosts failed - aborting script to avoid blacklisting IP on outbound emails"
	exit
else
	echo "updated /etc/hosts file"
fi
# start sendmail after fqdn is set in hosts file
service sendmail restart
# launch MSS script with args passed through docker run
./mss.sh "$malware" "$malware_description"