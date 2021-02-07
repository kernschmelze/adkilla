# adkilla
Highly configurable adblocker, also useful against malware and phishing.<br>
<h2>Highlights</h2>
<ul>
<li>Blacklist and whitelist can be edited to choose lists to download and use as well as individual domain/hostnames.
<li>Current configuration merges 55 well-selected ad, tracking, malware, phishing and telemetry site lists and one whitelist.
<li>Can read a multitude of adblocker list formats.
<li>Over 1.6 million hosts/domains blocked as of January 2021, <i>with almost no false-positives!</i>
<li>When using recursive (subdomain) blocking, the number of domains decreases to 600k, reducing memory usage too.
<li>Can export into DNS server configuration file format: Unbound (implemented) BIND and others (on request).
</ul>

Recommended usage: From crontab, about monthly update<br>
Recommended parameters:<br>
<br>
<b>adkilla -v --downloadstripmerge --unbound -r=127.0.0.1 -d=/var/adkilla -s -t=/var/unbound/unbound_include.txt -c=/usr/local/etc</b><br>
<br>
Parameter explanation:<br>
<b>-v</b> : more verbose output<br>
<b>--downloadstripmerge</b> : download, strip and merge the black+whitelists<br>
<b>--unbound</b> : create unbound include file in target directory<br>
[the following options need only to be set if not using the default values shown below]<br>
<b>-r=127.0.0.1</b> : set the IP to redirect to for blocked domains/hosts<br>
<b>-d=/var/adkilla</b> : use this directory as storage for downloaded and processed files<br>
<b>-s</b> : this option turns on blocking of subdomains of blacklisted domains<br>
<b>-t=/var/unbound/unbound_include.txt</b> : target path/filename for the unbound include file<br>
<b>-c=/usr/local/etc</b> : where the config files, i.e. black- and whitelists are.<br>
<br>
To see all available options, run <b>adkilla --help</b><br>
<br>
Please read the config files for more usage instructions:<br>
<b>adkilla_blacklist.conf</b> : blacklist file<br>
<b>adkilla_whitelist.conf</b> : whitelist file<br>
<br>
Do not forget to create the directories if they aren't there yet!<br>
If you are not running the script as root, the working and target directories must be set so the user can read and write!<br>
<br>
<h3>How it works</h3><br>
There are four passes:<br>
<ul>
<li>Download</li>
<li>Strip</li>
<li>Merge</li>
<li>Generate DNS include file for Unbound (and maybe others, on request)</li>
</ul><br>
<h4>Download</h4><br>
Every time this step is called, a subdirectory in the work directory is created, with the name "YYYY-MM-DD-HH:MM:SS".<br>
Thus you can keep older downloaded versions for archive etc.<br>
Space usage is low compared with modern storage sizes, about 100MB for all downloaded and resulting processed files. If you are concerned about space usage, install a packer or cleaner script.<br>
The chronologically as alphabetically latest directory created automatically becomes the work subdirectory for the following steps, too.<br>
The files are downloaded with their names consisting of their URL (with slashes and spaces replaced by an underscore), prefixed by "black" or "white", respective what kind the list is.<br>
<br>
<h4>Strip</h4><br>
As the blocklist files are in numerous formats, some even tarpacked, they have to be preprocessed.<br>
HTML, different ad blocker list formats, malformed list entries, other errors in lists and all this.<br>
The strip pass removes (almost) all this garbage, leaving only the domain/host names that are of interest to us.<br>
The result files have the same name as the originals, with added filename extension ".stripped".<br>
<br>
<h4>Merge</h4><br>
This pass merges the (in many cases redundant) information from the blocklists, so there are no double entries in the resulting final blocklist.<br>
Depending on whether you want recursive subdomain blocking (-s option) or normal non-recursive blocking, the resulting file size and memory usage differ considerably.<br>
As there is no need to store subdomains of already-blocked domains, the memory usage is considerably less when using the -s option.<br>
Using the current blocklists (Jan 2021), peak memory usage is <400MB compared to <1.4GB when using normal, non-recursive blocking.<br>
The result files from the merge pass are:<br>
blackmergefile.txt and whitemergefile.txt: These files contain the merged black and whitelists, respective.<br>
finalmergefile.txt: This file contains the final blacklist, consisting of the merged blacklist minus the merged whitelist.<br>
<br>
<h4>Generate DNS include file for Unbound (and maybe others, on request)</h4><br>
The final mergefile only consists hosts/domain names and this needs to be blown up so Unbound can use it.<br>
The way the resulting "unbound_include.txt" file gets blown up depends on your setting, default normal, or with -s option recursive, including subdomains.<br>
This file then gets copied into /var/unbound, if you specified no other target.<br>
<br>
<b>And now you can reload unbounds' configuration and enjoy a less annoying internet :)</b><br>








