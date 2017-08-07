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

## Usage
1. Populate configuration in `mss.conf`
2. Run `./mss.sh`

## Limitations
* Can only submit 1 sample at a time
* Web form submission not complete
* Ability to use custom SMTP server and related settings not complete