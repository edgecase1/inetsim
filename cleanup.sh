#! /bin/sh

# remove backup files
#for i in `find . -name "*~"`; do rm $i; done
# remove reports
for i in `find ./report/ -name "report.*.txt"`; do rm -f $i; done
# remove logfiles
rm -f ./log/main.log
rm -f ./log/service.log
rm -f ./log/debug.log
# remove HTTP postdata
for i in `find ./data/http/postdata/ -type f -not -regex ".*\/\.svn\/.*"`; do rm -f $i; done
# remove FTP uploads
for i in `find ./data/ftp/upload/ -type f -not -regex ".*\/\.svn\/.*"`; do rm -f $i; done
# remove TFTP uploads
for i in `find ./data/tftp/upload/ -type f -not -regex ".*\/\.svn\/.*"`; do rm -f $i; done
# remove service data (from older versions)
if [ -f ./data/pop3/pop3.dat ]; then
    rm -f ./data/pop3/pop3.dat
    rm -f ./data/pop3/session.dat
    rm -f ./data/pop3/session.lck
fi
if [ -f ./data/tftp/uploads.dat ]; then
    rm -f ./data/tftp/uploads.dat
    rm -f ./data/tftp/uploads.idx
fi
# remove service data
rm -f ./data/smtp/smtp.mbox
rm -f ./data/smtp/smtps.mbox
rm -f ./data/pop3/pop3.data ./data/pop3/pop3.lock ./data/pop3/pop3.session
rm -f ./data/pop3/pop3s.data ./data/pop3/pop3s.lock ./data/pop3/pop3s.session
#
