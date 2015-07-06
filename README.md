mwcrawler .09
=============

mwcrawler is a simple python script that parses malicious url lists from well 
known websites (i.e. MDL, Malc0de) in order to automatically download
the malicious code. It can be used to populate malware repositories or zoos.

The latest release of mwcrawler is maintained by and updated Francisco Donoso. The original author is Richardo Diaz:
https://github.com/0day1day/mwcrawler

Currently the script parses the following sources:
- Malware Domain List:
	http://www.malwaredomainlist.com/hostslist/mdl.xml
- VX Vault:
	http://vxvault.siri-urz.net/URL_List.php
- Malc0de:
	http://malc0de.com/rss
- ThreatGlass:
	http://threatglass.com
- CleanMX:
	http://support.clean-mx.de/clean-mx/viruses
- Zeus Tracker:
	https://zeustracker.abuse.ch

The downloaded content is stored in /opt/malware/unsorted/ by default. 
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

- BeautifulSoup 
	http://www.crummy.com/software/BeautifulSoup/

- Python Magic
	https://github.com/ahupp/python-magic

Usage:

```$ python mwcrawler.py```

Use '-t' for thug analysis:

```$ python mwcrawler.py -t```

Use '-d' to enable debug logging:

```$ python mwcrawler.py -t -d```

Use '-o' to attempt to download samples marked as "offline" by Zeus Tracker:

```$ python mwcrawler.py -t -d -o```


 

References:

thug repository - http://github.com/buffer/thug
