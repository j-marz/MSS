# Base image
FROM ubuntu:16.04

MAINTAINER John Marzella

# Update package repo and install dependencies
RUN apt-get update && apt-get install -y curl tee mailutils zip p7zip-full jq sendmail clamav

# Copy MSS files to image
RUN mkdir MSS
COPY mss.* /MSS/
COPY vendors* /MSS/

# Run MSS - expects cmdline args passed through docker run
WORKDIR /MSS
ENTRYPOINT ["./mss.sh"]
CMD []
