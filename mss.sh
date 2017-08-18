#!/bin/bash

###############################
# MSS - Malware Sample Sender #
###############################

# Created by: John Marzella

# Submit malware samples to all AV vendors listed in the config files
# The config files will contain submission requirements for each vendor (e.g. zip, password, filename, url, etc)
# Vendors that already detect the malware via VirusTotal will be skipped

# terminate script on any errors
set -e

# standard variables
config=mss.conf
vendors_email=vendors_email.conf
vendors_web=vendors_web.conf
log=mss.log
dependencies=(mail zip 7z jq)
mss_name="Malware Sample Sender"
mss_version="v0.2"
vt_api_scan_url="https://www.virustotal.com/vtapi/v2/file/scan"
vt_api_rescan_url="https://www.virustotal.com/vtapi/v2/file/rescan"
vt_api_report_url="https://www.virustotal.com/vtapi/v2/file/report"

# import main configuration
source $config

# ----- functions -----
# logging function
function log {
	echo "[$(date --rfc-3339=seconds)]: $*" >> $log
}

# check for dependencies
function dependency_check {
	log "checking dependencies"
	for dependency in "${dependencies[@]}"
		do
			if [ -x "$(command -v $dependency)" ]; then
		    	log "$dependency dependency exists"
			else
		    	log "$dependency dependency does not exist - please install using 'apt-get install $dependency'"
		    	abort
			fi
		done
	log "dependency check complete"
}

# check if file exists
function file_check {
	# $1 variable passed through when function is called
	if [ -f $1 ]; then
	log "$1 found"
else
	log "$1 not found - please create"
	abort
fi
}

# archive function
function create_archive {
	# set archive name
	archive_name=$filename.$archive_type
	# check archive type
	if [ $archive_type = "zip" ]; then
		# check if archive should be password protected
		if [ $archive_password != "none" ]; then
			# create archive without password
			zip $archive_name $filename &> /dev/null
		else
			# create archive with password
			zip $archive_name --password $archive_password $filename &> /dev/null
		fi
		# create sha256sum of archive for later use in email body
		archive_sha256="$(sha256sum $archive_name)"
		log "created $archive_type archive for $vendor_name - sha256sum $archive_sha256" 
	elif [ $archive_type = "7z" ]; then
		# check if archive should be password protected
		if [ $archive_password != "none" ]; then
			# create archive without password
			7z a $archive_name $filename &> /dev/null
		else
			# create archive with password
			7z a -p"$archive_password" $archive_name $filename &> /dev/null
		fi
		# create sha256sum of archive for later use in email body
		archive_sha256="$(sha256sum $archive_name)"
		log "created $archive_type archive for $vendor_name - sha256sum $archive_sha256"
	else
		# skip current lopp iteration if not zip or 7z
		log "unknown archive type for $vendor_name - no archive created - check $vendors_email"
		echo "unknown archive type for $vendor_name - no archive created - check $vendors_email"
		# loop control
		#continue # this doesn't work from within a function?
		loop_control="continue"
	fi
}

# send email function
function send_email {
#### TO DO #### need to add options for SMTP auth, SMTP server and SMTP port
	email_body_base="Malware sample attached"
	email_body_archvie_password="The sample has been encrypted with the following password: "$archive_password""
	email_body_checksum="SHA256SUM $archive_sha256"
	email_body_sample_description="Sample description: $description"
	email_body_signature="Sent using $mss_name $mss_version"
	# decide on email body based on archive password
	if [ $archive_password = "none" ]; then
		email_body="$email_body_base \n$email_body_sample_description \n$email_body_checksum \n \n$email_body_signature"
	elif [ -z $archive_password ]; then # this might be redundant if config values are checked at start of script
		email_body="$email_body_base \n$email_body_sample_description \n$email_body_checksum \n \n$email_body_signature"
	else
		email_body="$email_body_base \n$email_body_archvie_password \n$email_body_sample_description \n$email_body_checksum \n \n$email_body_signature"
	fi
	# send the email
	echo -e "$email_body" | mail -s "$email_subject" \
		-A $archive_name $vendor_email \
		-a From:$sender_email \
		-a Reply-To:$report_email \
		-a X-MSS:"$mss_name $mss_version" \
		-a Content-Type:"text/plain"
	# log
	log "malware sample submitted to $vendor_name via email - $vendor_email"
}

# clean up
function delete_archive {
	rm -f $archive_name
	log "deleted $archive_name"
	#### TO DO #### check if file exists
}

# check virustotal - report on virustotal results and skip vendors that already detect the malware in virustotal
function virustotal {
	#check if api key exists in config
	if [ -z $virustotal_api_key ]; then
		log "virustotal_api_key is null, skipping virustotal scans"
		echo "virustotal_api_key is null, skipping virustotal scans"
	else
		vt_scan="/tmp/vt_scan.json"
		vt_rescan="/tmp/vt_rescan.json"
		vt_report="/tmp/vt_report.json"
		vt_vendors="/tmp/vt_vendors.json"
		# submit sample to virustotal public api
			# consider changing this to search for sha256 instead of uploading file to save bandwidth and time
		curl -F file=@$filename -F apikey=$virustotal_api_key $vt_api_scan_url > $vt_scan
		# set variables from vt json response
		vt_scan_id="$(cat $vt_scan | jq '.scan_id' | awk -F '"' '{print $2}')" # must remove double quotes
		vt_sha256="$(cat $vt_scan | jq '.sha256' | awk -F '"' '{print $2}')" # must remove double quotes
		vt_rsp_code="$(cat $vt_scan | jq '.response_code')"
		vt_verbose_msg="$(cat $vt_scan | jq '.verbose_msg')"
		# log
		log "virustotal scan submitted - scan id: $vt_scan_id"
		echo "virustotal scan submitted - scan id: $vt_scan_id"
		log "virustotal verbose msg: $vt_verbose_msg"
		echo "virustotal verbose msg: $vt_verbose_msg"
		# determine next action based on response code
		if [ $vt_rsp_code -eq 0 ]; then
			log "no data exists in virustotal database - this is a brand new submission"
			echo "no data exists in virustotal database - this is a brand new submission"
			# wait for scan to complete - sleep for 30 seconds
			echo "waiting 30sec for virustotal scan to complete"
			sleep 30
			# retrieve scan report
			log "attempting to retrieve virustotal scan report"
			echo "attempting to retrieve virustotal scan report"
			curl --request POST --url $vt_api_report_url -d apikey=$virustotal_api_key -d resource=$vt_scan_id > $vt_report
			vt_rsp_code="$(cat $vt_report | jq '.response_code')"
			vt_verbose_msg="$(cat $vt_report | jq '.verbose_msg')"
			# retry if report isn't ready
			if [ $vt_rsp_code -eq -2 ]; then
				while [ $vt_rsp_code -eq -2 ]; do
					log "virustotal verbose msg: $vt_verbose_msg"
					echo "virustotal verbose msg: $vt_verbose_msg"
					log "sleeping for another 30sec..."
					echo "sleeping for another 30sec..."
					sleep 30
					log "attempting to retrieve virustotal scan report"
					echo "attempting to retrieve virustotal scan report"
					curl --request POST --url $vt_api_report_url -d apikey=$virustotal_api_key -d resource=$vt_scan_id > $vt_report
					vt_rsp_code="$(cat $vt_report | jq '.response_code')"
					vt_verbose_msg="$(cat $vt_report | jq '.verbose_msg')"
				done
#### note: should check other response codes here...
			fi
			# write vendors to file for later checks
			cat $vt_report | jq '.scans | . as $object | keys[] | select($object[.].detected == true)' > $vt_vendors
			# set variables
			vt_total="$(cat $vt_report | jq '.total')"
			vt_positives="$(cat $vt_report | jq '.positives')"
			vt_scan_date="$(cat $vt_report | jq '.scan_date')"
			vt_permalink="$(cat $vt_report | jq '.permalink')"
			# log
			log "virustotal report scan date: $vt_scan_date"
			echo "virustotal report scan date: $vt_scan_date"
			log "virustotal report link: $vt_permalink"
			echo "virustotal report link: $vt_permalink"
			log "$vt_positives out of $vt_total vendors detected file as malware through virustotal"
			echo "$vt_positives out of $vt_total vendors detected file as malware through virustotal"
		elif [ $vt_rsp_code -eq 1 ]; then
			log "file found in virustotal database - rescaning to get latest detection results"
			echo "file found in virustotal database - rescaning to get latest detection results"
			# wait 2 seconds - probably not required...
			sleep 2
			# rescan file using sha256sum to get latest results from virustotal
			curl --request POST --url $vt_api_rescan_url -d apikey=$virustotal_api_key -d resource=$vt_sha256 > $vt_rescan
			vt_scan_id="$(cat $vt_rescan | jq '.scan_id' | awk -F '"' '{print $2}')" # must remove double quotes
			vt_verbose_msg="$(cat $vt_rescan | jq '.verbose_msg')"
			log "virustotal rescan submitted - scan id: $vt_scan_id"
			echo "virustotal rescan submitted - scan id: $vt_scan_id"
			log "virustotal verbose msg: $vt_verbose_msg"
			echo "virustotal verbose msg: $vt_verbose_msg"
			# wait for scan to complete - sleep for 30 seconds
			echo "waiting 30sec for virustotal rescan to complete"
			sleep 30
			# retrieve scan report
			log "attempting to retrieve virustotal scan report"
			echo "attempting to retrieve virustotal scan report"
			curl --request POST --url $vt_api_report_url -d apikey=$virustotal_api_key -d resource=$vt_scan_id > $vt_report
			vt_rsp_code="$(cat $vt_report | jq '.response_code')"
			vt_verbose_msg="$(cat $vt_report | jq '.verbose_msg')"
			# retry if report isn't ready
			if [ $vt_rsp_code -eq -2 ]; then
				while [ $vt_rsp_code -eq -2 ]; do
					log "virustotal verbose msg: $vt_verbose_msg"
					echo "virustotal verbose msg: $vt_verbose_msg"
					log "sleeping for another 30sec..."
					echo "sleeping for another 30sec..."
					sleep 30
					log "attempting to retrieve virustotal scan report"
					echo "attempting to retrieve virustotal scan report"
					curl --request POST --url $vt_api_report_url -d apikey=$virustotal_api_key -d resource=$vt_scan_id > $vt_report
					vt_rsp_code="$(cat $vt_report | jq '.response_code')"
					vt_verbose_msg="$(cat $vt_report | jq '.verbose_msg')"
				done	
#### note: should check other response codes here...
			fi
			# write vendors to file for later checks
			cat $vt_report | jq '.scans | . as $object | keys[] | select($object[.].detected == true)' > $vt_vendors
			# set variables
			vt_total="$(cat $vt_report | jq '.total')"
			vt_positives="$(cat $vt_report | jq '.positives')"
			vt_scan_date="$(cat $vt_report | jq '.scan_date')"
			vt_permalink="$(cat $vt_report | jq '.permalink')"
			# log
			log "virustotal report scan date: $vt_scan_date"
			echo "virustotal report scan date: $vt_scan_date"
			log "virustotal report link: $vt_permalink"
			echo "virustotal report link: $vt_permalink"
			log "$vt_positives out of $vt_total vendors detected file as malware through virustotal"
			echo "$vt_positives out of $vt_total vendors detected file as malware through virustotal"
		else 
			log "unexpected response code from virustotal - response_code: $vt_rsp_code"
			echo "unexpected response code from virustotal - response_code: $vt_rsp_code"
			log "aborting virustotal scan"
			echo "aborting virustotal scan"
			log "sample will be submitted to all vendors"
			echo "sample will be submitted to all vendors"
		fi
	fi
}

# lookup vendor name in vt results
	# requires vendor names from config to match vt results
function vt_lookup {
	# check if VT results exist
	if [ -f $vt_vendors ]; then
		# skip current loop iteration if vendor detected malware in virustotal scan
		if grep -Fiq $vendor_name $vt_vendors; then
			log "$vendor_name detected malware through virustotal - skipping submission"
			echo "skipping submission"
			# loop control
			#continue # this doesn't work from within a function?
			loop_control="continue"
		else
			# continue with sample submission
			log "$vendor_name did not detect malware through virustotal - proceeding to sample submission"
			echo "sending sample"
		fi
	else
		# continue with sample submission
		log "unable to determine if $vendor_name detected via virustotal due to missing virustotal results - $vt_vendors"
		echo "sending sample"
	fi
}

function vt_cleanup {
	# clean up tmp files
	rm /tmp/vt_*.json
}

function progress {
	# display vendor name and progress
	echo "vendor $counter of $vendor_total - $vendor_name"
	# add +1 to counter
	let counter=counter+1
}

function abort {
	echo "something went wrong..."
	echo "please review $log"
	echo "script will abort in 5 seconds"
	sleep 5
	log "aborting mss script due to errors"
	exit
}

function finish {
	echo "MSS has finished"
	log "mss.sh finished"
	exit
}

# ----- script -----

# start logging
log "mss.sh started"

# check dependencies
dependency_check

# check configs exist
file_check $config
file_check $vendors_email
file_check $vendors_web

# store working directory in variable
wd="$(pwd)"

# set sample file - ask user for interactive input
read -p "Sample filename from $wd (e.g. sample.exe): " filename
log "sample filename: $filename"
file_check $filename

# set sample description - ask user for interactive input
read -p "Sample description (e.g. received via phishing email): " description
log "sample description: $description"

# count number of vendors
vendor_total="$(grep -v '^$\|^#' $vendors_email | wc -l)"
log "$vendor_total vendors configs loaded"

# virustotal scans
virustotal

# start vendor counter at 1
counter=1

# email submission loop
grep -v '^$\|^#' $vendors_email | while IFS=, read col1 col2 col3 col4 col5
	do
		# assign columns to variables
		vendor_name=$col1
		vendor_email=$col2
		email_subject=$col3
		archive_type=$col4
		archive_password=$col5
		# run functions 
		#### TO DO ####
			# split file path and file name so email and attachemnt are named correctly
				# added $wd to input comment to avoid user supplying full path :(
		progress
		vt_lookup
		# loop control for functions
		if [[ $loop_control = "continue" ]]; then
			# clear variable
			loop_control=""
			continue
		fi
		create_archive
		# loop control for functions
		if [[ $loop_control = "continue" ]]; then
			# clear variable
			loop_control=""
			continue
		fi
		send_email
		delete_archive
	done

# web submission loop


# clean up
vt_cleanup

# done
finish

#### TO DO ####
# config should be validated (NTH)
	# check values in config
	# print config to screen and ask user to confirm?

# virustotal vendor check
	# compare vendor list with config and notify user if vendor contact doesn't exist for sample submission

# web form submission
#function web_form_submission {
	# send using cURL
	# check response status code for success
#}
# md5sum the config files and report on change during next run?
# NTH

# The same archive should be used for multiple submissions where configs match
# Creating archives for vendors that have the same config is not efficient