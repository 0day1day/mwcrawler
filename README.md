mwcrawler
=========

mwcrawler is a simple python script that parses malicious url lists from well 
known websites (i.e. MDL, Malc0de) in order to automatically download
the malicious code. It can be used to populate malware repositories or zoos.

Currently the script parses the following sources:
- NovCon Minotaur:
	http://minotauranalysis.com/malwarelist-urls.aspx
- Malware Domain List:
	http://www.malwaredomainlist.com/hostslist/mdl.xml
- VX Vault:
	http://vxvault.siri-urz.net/URL_List.php
- Malc0de:
	http://malc0de.com/rss
- Malware Black List:
	http://www.malwareblacklist.com/mbl.xml
- Sacour.cn:
	http://www.sacour.cn

The downloaded content is stored in /opt/malware/unsorted/ by default, so you 
need to create this folder first, or change the source code otherwise.
Sub-folders will be created, based on the magic numbers of the downloaded
content (i.e. PE32, PDF, ZIP). For the sake of simplicity note that the script
splits the file description string and only use the first 'token'.

The file name is set based on the calculated MD5 hash, which is also used to
check if the file exists, thus avoiding duplicate entries in the directories.
Please note that the original file name (set in the url or http header) is 
ignored.

Additionally if you have Angelo Dell'Aera's *thug* installed, you can enable 
html code for low interaction analysis.


Requirements:

- BeautifulSoup 3.0.8 (later versions seem to have problems parsing html):
	http://www.crummy.com/software/BeautifulSoup/


Usage:

$ python mwcrawler.py

Use '-t' for thug analysis
$ python mwcrawler.py -t


References:

thug repository - http://github.com/buffer/thug
