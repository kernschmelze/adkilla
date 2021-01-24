# adkilla
Highly configurable adblocker, also useful against malware and phishing.<br>
Blacklist and whitelist can be edited to choose lists to download and use as well as individual domain/hostnames.<br>
Can use a multitude of ad blocker list formats.<br>
Can export into various configuration file formats: Unbound (working), BIND (planned), others (requests?).<br>

Recommended usage: From crontab, about monthly update<br>
Recommended parameters:<br>
<b>adkilla -v --downloadstripmerge --unbound -r=127.0.0.1 -d=/var/adkilla -t=/var/unbound -c=/usr/local/etc</b><br>
Parameter explanation:<br>
<b>-v</b> : more verbose output<br>
<b>--downloadstripmerge</b> : download, strip and merge the black+whitelists<br>
<b>--unbound</b> : create unbound include file in target directory<br>
[the following options need only to be set if not using the default values shown below]<br>
<b>-r=127.0.0.1</b> : set the IP to redirect to for blocked domains/hosts<br>
<b>-d=/var/adkilla</b> : use this directory as storage for downloaded and processed files<br>
<b>-t=/var/unbound</b> : target path/filename for the unbound include file<br>
<b>-c=/usr/local/etc</b> : where the config files, i.e. black- and whitelists are.<br>
<br>
The config files are:<br>
Please read them for more usage instructions.<br>
<b>adkilla_blacklist.conf</b> : blacklist file<br>
<b>adkilla_whitelist.conf</b> : whitelist file<br>
<br>
Do not forget to create the directories if they aren't there yet!<br>
If you are not running as root, the working and target directories must be set so the user can read and write!<br>


