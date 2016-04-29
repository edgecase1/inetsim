#!/bin/sh
#
# INetSim setup script
#
# Sets some required file permissions
#
# This script must be run as root!
#

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

if [ `id -u 2>/dev/null` -ne 0 ]; then
  echo "This script must be run as root! Aborting."
  exit 1
fi

if ! grep -q '^inetsim:' /etc/group; then
  echo "Group 'inetsim' does not exist! Aborting."
  exit 1
fi

if [ ! -f ./data/certs/default_key.pem ]; then
  if openssl version >/dev/null 2>&1; then
    echo -n "Creating default SSL key and certificate... "
    openssl req -new -x509 -days 3650 -nodes -sha1 -keyout ./data/certs/default_key.pem -out ./data/certs/default_cert.pem -subj "/O=INetSim/OU=Development/CN=inetsim.org" 2>/dev/null && echo "done." || echo "failed."
  else
    echo "NOT creating default SSL key and certificate: OpenSSL not found."
    echo "Check PATH in setup script if you have installed OpenSSL at an unusual location."
  fi
fi

echo -n "Setting file permissions... "

chgrp -R inetsim ./log
chmod 770 ./log

chgrp inetsim ./report
chmod 770 ./report

chgrp -R inetsim ./data
chmod g+w ./data/http/postdata/
chmod g+w ./data/ftp/upload/
chmod g+w ./data/tftp/upload/

echo "done."
#
