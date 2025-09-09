# CredStorm
A tool for Password Spraying multiple IPs and Services.

============

**Usage**

python CredStorm.py -t targets.txt -u users.txt -p passwords.txt

python CredStorm.py -t targets.txt -u users.txt -p passwords.txt --sleep 2 --threads 5 --output hits.log


============

**Example of targets.txt**

10.10.10.1 "ssh,ftp,http-get"

10.10.10.2 "ssh"
