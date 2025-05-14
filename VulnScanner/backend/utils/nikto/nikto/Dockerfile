FROM perl:latest

LABEL version="2.5.0" \
      author="Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter" \
      docker_build="docker build -t sullo/nikto:2.5.0 ." \
      docker_run_basic="docker run --rm sullo/nikto:2.5.0 -h http://www.example.com" \
      docker_run_advanced="docker run --rm -v $(pwd):/tmp sullo/nikto:2.5.0 -h http://www.example.com -o /tmp/out.json"

# Install necessary packages
RUN echo 'Installing packages for Nikto.' \
  && apt-get update \
  && apt-get install -y \
    git \
    openssl \
    libnet-ssleay-perl \
    libwww-perl \
    libwhisker2-perl

# Clone the Nikto repository
RUN git clone https://github.com/sullo/nikto.git /opt/nikto

# List the contents of the /opt/nikto directory to debug the file location
RUN echo "Listing contents of /opt/nikto" && ls -R /opt/nikto

# Make sure nikto.pl is executable
RUN chmod +x /opt/nikto/program/nikto.pl

# Create a user and group for nikto
RUN groupadd -r nikto && useradd -r -g nikto nikto

USER nikto

# Set the working directory to the correct path for nikto.pl
WORKDIR /opt/nikto/program

# Default entrypoint
ENTRYPOINT ["/opt/nikto/program/nikto.pl"]
