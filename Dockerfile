# Base image
FROM ubuntu:latest

MAINTAINER John Marzella

# Update package repo and install dependencies
RUN apt-get update && \
	apt-get install -y curl mailutils zip p7zip-full jq sendmail clamav

# Copy MSS files to image
RUN mkdir MSS
COPY mss.* /MSS/
COPY vendors* /MSS/
COPY docker-entrypoint.sh /MSS/

# Set up SMTP server and run MSS (expects cmdline args passed through docker run)
WORKDIR /MSS
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD []
