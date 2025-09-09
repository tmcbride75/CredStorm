# Spit
A tool for Password Spraying multiple IPs and Services.

============

**Usage**

python Spit.py -t targets.txt -u usernames.txt -p passwords.txt

python Spit.py -t targets.txt -u usernames.txt -p passwords.txt --sleep 2 --threads 5 --output hits.log


============

**Example of targets.txt**

10.10.10.1 "ssh,ftp,http-get"

10.10.10.2 "ssh"
