#!/usr/bin/python
# Copyright (C) 2012 Ricardo Dias
#
# Updated 07/05/2015
# Updated by Francisco Donoso 
# Malware Crawler Module v0.9
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Requirements:
# - BeautifulSoup 4.0
# - File magic

	

from BeautifulSoup import BeautifulSoup as bs
import sys
import hashlib
import re
import urllib2
import magic
import os 
import socket
import datetime
import logging
import re
import argparse

# By default thug analyis is disabled
isthug	= False

# variable for date value manipulation
now		= datetime.datetime.now()
str(now)

# maximum wait time of http gets
timeout	= 15
socket.setdefaulttimeout(timeout)

# load thug function, also checks if thug is installed
def loadthug():
	try:
		sys.path.append('/opt/thug/src') #add /opt/thug/src to the list of places to search for modules
		global thug
		import thug
		global isthug
		isthug = True
		logging.info("Thug module loaded for html analysis")
	except ImportError:
		logging.error("No Thug module found, html code inspection won't be available. Please verify Thug Path")

#Use filemagic to determine filetype - now uses the same module as Thug
def gettype(file):
	file_type = magic.from_buffer(file)
	logging.debug("File: %s is filetype %s",file,file_type)
	return file_type

#Automatically send to Thug

def thugOnly(url):
    if not re.match('http',url):
        url = 'http://'+url

    if isthug:
        logging.info("Thug candidate: HTML code in %s",url)

        try:
            thug.Thug([url])()
        except Exception, e:
            logging.error("thug error: %s",e)
            return

# beautifulsoup parser
def parse(url):
	logging.debug("Trying to parse the following source: %s",url)
	request = urllib2.Request(url)
	request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
	try:
		http = bs(urllib2.urlopen(request)) #grab a soup object and name it http
	except:
		logging.error("Error parsing %s",url)
		return
	return http #return the http object

#decide what to do with the malicious urls
def decisor(url):
	logging.debug("trying to decide what to do with: %s",url)
	if not re.match('http',url): 
		url = 'http://'+url 

	try:
		url_dl = urllib2.urlopen(url).read()
		logging.debug("getting the contents of the malware URL: %s",url)
	except Exception, e:
		logging.error("-- Error: %s on %s",e,url)
		return

	filetype = gettype(url_dl).split(' ')[0]
	logging.debug("the filetype is: %s",filetype)
	md5      = hashlib.md5(url_dl).hexdigest() 

	if (filetype == 'HTML'): 
		if isthug:
			logging.info("Thug candidate: HTML code in %s",url)

			try:
				thug.Thug([url])()
			except Exception, e:
				logging.error("Thug error: %s",e)
				return

	else:
		dest = '/opt/malware/unsorted/'+filetype 
		logging.debug("Going to put this in %s",dest)
		fpath = dest+'/'+str(md5) 
		logging.debug("the filepath will be: %s",fpath)

		if not os.path.exists(dest): 
			os.makedirs(dest)

		if not os.path.exists(fpath):
			file = open(fpath, 'wb') 
			file.write(url_dl)
			file.close
			logging.info("Saved file type %s with md5: %s",filetype,md5)

#we know the file is not HTML just download it
def downloader(url):
	if not re.match('http',url):
		url = 'http://'+url

	try:
		url_dl = urllib2.urlopen(url).read() 
		logging.debug("getting the contents of the malware URL: %s",url)
	except Exception, e:
		logging.debug("Unable to download: %s due to: %s",url,e)
		return

	filetype = gettype(url_dl).split(' ')[0]
	logging.debug("the filetype is: %s",filetype)
	md5      = hashlib.md5(url_dl).hexdigest() 

	dest = '/opt/malware/unsorted/'+filetype #one folder per filetype
	logging.debug("Going to put this in %s",dest)
	fpath = dest+'/'+str(md5) 
	logging.debug("the filepath will be: %s",fpath)

	if not os.path.exists(dest): 
		os.makedirs(dest)

	if not os.path.exists(fpath): 
		file = open(fpath, 'wb') 
		file.write(url_dl)
		file.close
		logging.info("-- Saved file type %s with md5: %s",filetype,md5)

#remove the data from ThreatGlass URLs
def removedate(threat):
	p = re.compile(ur'.\d{4}.((0\d)|(1[012])).(([012]\d)|3[01])')
	return re.sub(p,'',threat)

#Parse data from ThreatGlass
def parseThreatGlass(soup):
	logging.info("Fetching from TheatGlass")
	tglist = []
	for tag in soup.findAll('a', href=True): 
		tglist.append(tag['href'])
	del tglist[:5] #remove all of their header links
	del tglist[-1] #remove links to the next page
	tglist = set(tglist) #only attempt to download unique urls
	logging.info("Found %s urls on this page on ThreatGlass",len(tglist))
	for each in tglist: 
		thugOnly(removedate(str(each.split('/malicious_urls/')[1]).replace('-','.'))) 

#threatglass page crawler
def threatGlass(pages):
	logging.info("Getting %s pages from ThreatGlass",pages)
	for tile in range(1,pages+1):
		parseThreatGlass(parse('http://threatglass.com/tiles?page=' + str(tile)))

def malwaredl(soup):
	logging.info("Fetching from Malware Domain List")
	mdl=[]
	for row in soup('description'): 
		mdl.append(row) 
	del mdl[0] 
	mdl_sites=[] 
	for row in mdl:
		site = re.sub('&amp;','&',str(row).split()[1]).replace(',','') #replace ampersand and remove ,
		if site == '-':
			mdl_sites.append(re.sub('&amp;','&',str(row).split()[4]).replace(',','')) #heh
		else:
			mdl_sites.append(site) 
	mdl_sites = set(mdl_sites) 
	logging.info("Found %s urls on Malware Domain List",len(mdl))
	for row in mdl_sites:
		decisor(row)

#VxVault
def vxvault(soup):
	logging.info("Fetching from VXVault")
	vxv=[] 
	for row in soup('pre'): 
		vxv = row.string.split('\r\n')
	del vxv[:4] #remove all of the non malware url stuff
	del vxv[-1] #delete the useless last row
	vxv = set(vxv) #only attempt to download unique urls
	logging.info("Found %s urls from VXVault",len(vxv))
	for row in vxv:
		decisor(row) #decide and download

#Malcode Parser
def malc0de(soup):
	logging.info("Fetching from Malc0de")
	mlc=[] 
	for row in soup('description'): 
		mlc.append(row) 
	del mlc[0]
	mlc_sites=[] 
	for row in mlc:
		site = re.sub('&amp;','&',str(row).split()[1]).replace(',','') 
		mlc_sites.append(site)
	mlc_sites = set(mlc_sites) #
	logging.info("Found %s urls from Malc0de",len(mlc_sites))
	for row in mlc_sites:
		decisor(row)

#Malware BlackList parser
def malwarebl(soup):
	logging.info("Fetching from Malware Black List")
	mbl=[]
	for row in soup('description'):
		site = str(row).split()[1].replace(',','')
		mbl.append(site)
	mbl = set(mbl) 
	logging.info("Found %s urls from Malware Black List",len(mbl))
	for row in mbl:
		decisor(row)

#CleanMX parser
def cleanmx(soup):
	logging.info("Fetchingg from clean-mx.de")
	cmxlist = []
	for each in soup.body.findAll('a', href=True, title="open Url in new Browser at your own risk !"):
		site = re.sub('&amp;','&',str(each['href']))
		site = urllib2.unquote(site).decode('utf8')
		logging.debug("cleanmx parser was able to parse out: %s ",site)
		cmxlist.append(site)
	cmxlist = set(cmxlist) 
	logging.info("found %s urls from clean-mx.de",len(cmxlist))
	for site in cmxlist:
		decisor(site)

#zeus tracker binaries
def zeustrackerbin(soup):
	logging.info("Fetching from Zeus Tracker Binaries RSS feed")
	ztlist = []
	offline_list = []
	for each in soup('description'):
		ztlist.append(each)
	del ztlist[0]
	for entry in ztlist:
		url = re.search('(?:URL: )([^,]+)',str(entry)).group(1)
		status = re.search('(?:status: )([^,]+)',str(entry)).group(1)
		if args.offline:
			logging.debug("attempting to download %s regarless of status",url)
			downloader(url)
		if status == "offline":
			logging.debug("%s is marked as offline will not be downloaded",url)
			offline_list.append(url)
		else:
			downloader(url)
	if len(offline_list) == len(ztlist):
		logging.warning("All parsed items listed as offline. Use -o to attempt to download anyway")

#zeus tracker HTML
def zeustrackerhtml(soup):
	logging.info("Fetching from Zeus Tracker DropZones RSS feed")
	if not args.thug:
		logging.warning("Thug analysis not enabled. Zeus Tracker dropzone will not be processed")
	ztlist = []
	for each in soup('description'):
		ztlist.append(each)
	del ztlist[0]
	offline_list = []
	for entry in ztlist:
		url = re.search('(?:URL: )([^,]+)',str(entry)).group(1)
		status = re.search('(?:status: )([^</]+)',str(entry)).group(1)
		if args.offline:
			logging.debug("attempting to download %s regarless of status",url)
			thugOnly(url)
		else:
			if status == "offline":
				logging.debug("%s is marked as offline will not be downloaded",url)
				offline_list.append(url)
			else:
				thugOnly(url)
	if len(offline_list) == len(ztlist):
		logging.warning("All parsed items listed as offline. Use -o to attempt to download anyway")

if __name__ == "__main__":
	print "Malware Crawler v0.9"

	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--thug", help="Enables the thug plugin for html analysis", action="store_true")
	parser.add_argument("-d", "--debug", help="Enables debug logging for Malware Crawler", action="store_true")
	parser.add_argument("-o", "--offline", help="Attempts to download items marked as offline", action="store_true")
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level=logging.DEBUG, 
							format='%(asctime)s - %(levelname)s - %(message)s', 
							datefmt='%Y-%m-%d %H:%M:%S')
	else:
		logging.basicConfig(level=logging.INFO, 
							format='%(asctime)s - %(levelname)s - %(message)s', 
							datefmt='%Y-%m-%d %H:%M:%S')

	try:
		if args.thug:
			loadthug()
		else:
			logging.warning("Thug analysis not enabled (use -t to enable thug)")
	except Exception, e:	
		logging.error("loading thug failed with: %s",e)
		pass

	#source list
	try:
		malwaredl(parse('http://www.malwaredomainlist.com/hostslist/mdl.xml')) 
	except Exception, e:
		logging.error("Couldn't fetch data from Malware Domain List because of: %s",e)
		pass
	try:
		vxvault(parse('http://vxvault.siri-urz.net/URL_List.php')) 
	except Exception, e:
		logging.error("Couldn't fetch data from vxvault because of: %s",e)
		pass
	try:
		malc0de(parse('http://malc0de.com/rss')) 
	except Exception, e:
		logging.error("Couldn't fetch data from malcode because of: %s",e)
		pass
	try:
		threatGlass(10)
	except Exception, e:
		logging.error("Coudn't fetch data from ThreatGlass because of: %s",e)
		pass
	try:
		cleanmx(parse('http://support.clean-mx.de/clean-mx/viruses'))
	except Exception, e:
		logging.error("Couldn't fetch data from clean-mx because of: %s",e)
		pass
	try:
		zeustrackerbin(parse('https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries'))
	except Exception, e:
		logging.error("Couldn't fetch data from ZeusTracker Binary RSS because of: %s",e)
		pass
	try:
		zeustrackerhtml(parse('https://zeustracker.abuse.ch/monitor.php?urlfeed=dropzones'))
	except Exception, e:
		logging.error("Couldn't fetch data from ZeusTracker DropZones RSS because of: %s",e)
		pass
