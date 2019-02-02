# MSS
Malware Sample Sender

Submit malware samples to almost all AV vendors in an effort to improve malware detection across the board.
Uses vendor specific configs for sample submission and also skips vendors that already detect the malware based on VirusTotal scan results.

## Dependencies
* mail
* zip
* 7z
* jq
* local SMTP server (e.g. sendmail or postfix)

Install all dependencies on Ubuntu using `sudo apt-get install mailutils zip p7zip-full jq sendmail`

Note, make sure your FQDN is set in /etc/hosts so your IP doesn't get blacklisted for using default `localhost.localdomain`
Example `127.0.0.1	computer.mydomain.com computer localhost`

## Usage
1. Populate configuration in `mss.conf`
2. Run `./mss.sh`

## Limitations
* Can only submit 1 sample at a time
* Web form submission not complete
* Ability to use custom SMTP server and related settings not complete