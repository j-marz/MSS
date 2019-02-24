# MSS
Malware Sample Sender

Submit malware samples to almost all AV vendors in an effort to improve malware detection across the board.
Uses vendor specific configs for sample submission (email, web, tool) and also skips vendors that already detect the malware based on VirusTotal scan results.

## Dependencies
* mail
* zip
* 7z
* jq
* curl
* tee
* local SMTP server (e.g. sendmail or postfix)

Install all dependencies on Ubuntu using `sudo apt-get install mailutils zip p7zip-full jq sendmail`

## Optional Dependencies
* clamsubmit - cli tool included in clamav package to submit false negative samples - `sudo apt-get install clamav`

## Configuration
1. Add email address that will send samples and an email address that will receive reports from AV vendors in `mss.conf`
2. Add VT API key in `mss.conf`
3. Make sure your FQDN is set in /etc/hosts so your IP doesn't get blacklisted for using a default value like `localhost.localdomain` in SMTP HELO/EHLO. Example hosts file entry `127.0.0.1	computer.mydomain.com computer localhost`

## Usage
### Interactive 
1. Run `./mss.sh`
2. Follow the prompts for malware file and description

### Non-Interactive
1. Run `./mss.sh "/path/to/malware" "description of the malware for VT comments"`

### Docker
1. Clone repo `git clone https://github.com/j-marz/MSS.git`
2. Change working dir `cd MSS`
3. Update `mss.conf` config using your preferred text editor
4. Build docker image `sudo docker build -t mss .`
5. Run docker container and pass through samples using volume mount `sudo docker run -v /local/path/to/malware:/tmp/malware:ro -it mss "/tmp/malware" "description of the malware for VT comments"`

## Limitations
* Can only submit 1 sample at a time
* Web form submissions not complete
* Uses local SMTP server