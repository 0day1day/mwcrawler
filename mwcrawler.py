#!/usr/bin/python
# Copyright (C) 2012 Ricardo Dias
#
# Malware Crawler Module v0.4
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
# - BeautifulSoup 3.0.8
# Original script by Ricardo Dias
# 1) Added more sources
# 2) Fix some errors login etc...

from BeautifulSoup import BeautifulSoup as bs
import sys
import hashlib
import re
import urllib2
import magic
import os
import socket
import datetime
import argparse
import logging
import tempfile

# By default thug analyis is disabled
isthug    = False

# variable for date value manipulation
now        = datetime.datetime.now()
str(now)

# maximum wait time of http gets
timeout    = 15
socket.setdefaulttimeout(timeout)

# load thug function, also checks if thug is installed
def loadthug():
    try:
        sys.path.append('/opt/thug/src')
        import thug
        isthug = True
        logging.info("Thug module loaded for html analysis")
    except ImportError:
        logging.warning("No Thug module found, html code inspection won't be available")

# determine file type for correct archival
def gettype(file):
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    return ms.buffer(file)

# beautifulsoup parser
def parse(url):
    request = urllib2.Request(url)
    request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
    try:
        http = bs(urllib2.urlopen(request, timeout=60))
    except:
        logging.error('Error parsing %s',url)
        return
    return http

def decisor(url):
    if not re.match('http',url):
        url = 'http://'+url

    try:
        url_dl = urllib2.urlopen(url).read()
    except Exception, e:
        logging.error('Could not fetch %s', url)
        return

    filetype = gettype(url_dl).split(' ')[0]
    md5      = hashlib.md5(url_dl).hexdigest()

    if (filetype == 'HTML'):
        if isthug:
            logging.debug('Thug candidate: HTML code in %s', url)

            try:
                thug.Thug([url])()
            except Exception, e:
                logging.error('Thug error: %s', e)
                return

    else:
        dest = dumpdir+'/unsorted/'+filetype
        fpath = dest+'/'+str(md5)

        if not os.path.exists(dest):
            os.makedirs(dest)

        if not os.path.exists(fpath):
            file = open(fpath, 'wb')
            file.write(url_dl)
            file.close
            logging.info("Saved file type %s with md5 %s from URL %s", filetype, md5, url)
        else:
            logging.debug("Found duplicate of file with md5 %s on URL %s", md5, url)

def malwaredl(soup):
    logging.info("Fetching from Malware Domain List")
    mdl=[]
    for row in soup('description'):
        mdl.append(row)
    del mdl[0]
    mdl_sites=[]
    for row in mdl:
        site = re.sub('&amp;','&',str(row).split()[1]).replace(',','')
        if site == '-':
            mdl_sites.append(re.sub('&amp;','&',str(row).split()[4]).replace(',',''))
        else:
            mdl_sites.append(site)
    logging.info('Found %s urls', len(mdl))
    for row in mdl_sites:
        decisor(row)

def vxvault(soup):
    logging.info("Fetching from VXVault")
    vxv=[]
    for row in soup('pre'):
        vxv = row.string.split('\r\n')
    del vxv[:4]
    del vxv[-1]
    logging.info('Found %s urls', len(vxv))
    for row in vxv:
        decisor(row)

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
    logging.info('Found %s urls', len(mlc_sites))
    for row in mlc_sites:
        decisor(row)

def malwarebl(soup):
    logging.info("Fetching from Malware Black List")
    mbl=[]
    for row in soup('description'):
        site = str(row).split()[1].replace(',','')
        mbl.append(site)
    logging.info('Found %s urls', len(mbl))
    for row in mbl:
        decisor(row)

def minotaur(soup):
    logging.info("Fetching from NovCon Minotaur")
    minsites=[]
    for row in soup('td'):
        try:
            if re.match('http',row.string):
                minsites.append(row.string)
        except:
            pass
    logging.info('Found %s urls', len(minsites))
    for row in minsites:
        decisor(row)

def sacour(soup):
    logging.info("Fetching from Sacour.cn")
    for url in soup('a'):
        sacsites=[]
        if re.match('list/',url['href']):
            suburl = parse('http://www.sacour.cn/'+url['href'])
            for text in suburl('body'):
                for urls in text.contents:
                    if re.match('http://',str(urls)):
                        sacsites.append(str(urls))
        if len(sacsites) > 0:
            logging.info('Found %s urls in %s', len(sacsites),url['href'])
            for row in sacsites:
                decisor(row)

#----------------------------------------------------------------------
# Extra

def onlyThug(url):
    if not re.match('http',url):
        url = 'http://'+url

    if isthug:
        logging.debug('Thug candidate: HTML code in %s', url)

        try:
            thug.Thug([url])()
        except Exception, e:
            logging.error('Thug error: %s', e)
            return


def cleanmxparserow(soup, attrClass):
	cols=soup.findAll('td', {'class':attrClass})
	if len(cols)==0:
		return
	lastcol=cols[len(cols)-1]
	ases=lastcol.findAll('a', href=True)
	if len(ases)==0:
		return
	lasta=ases[len(ases)-1]
	return lasta['href']


def cleanMx(soup):
	logging.info("Fetching from Clean MX")
	table=soup.find('table', {'class':'liste'})
	rows=table.findAll('tr')
	urls=[]
	for row in rows:
		url=cleanmxparserow(row, 'zellen01')
		if url:
			urls.append(url)
		url=cleanmxparserow(row, 'zellennormal')
		if url:
			urls.append(url)

	for url in urls:
		decisor(url)


def spyEyeTracker(soup):
	logging.info("Fetching from SpyEye Tracker")
	table=soup.find('table', {'class':'table'})
	rows=table.findAll('tr')
	urls=[]
	for row in rows:
		columns=row.findAll('td')
		if columns[1].find('a'):
			urls.append(columns[1].a.string)

	for url in urls:
		decisor(url)


def zeusTracker(soup):
	logging.info("Fetching from Zeus Tracker")
	table=soup.find('table', {'class':'table'})
	rows=table.findAll('tr')
	urls=[]
	for row in rows:
		columns=row.findAll('td')
		if columns[1].find('a'):
			urls.append(columns[1].find('a').string)

	for url in urls:
		decisor(url)


def mwisRu(soup):
	logging.info("Fetching from mwis.ru")
	rows=soup.findAll('tr')
	urls=[]
	for row in rows:
		columns=row.findAll('td')
		if len(columns)>=3:
			if columns[2].find('a'):
				urls.append(columns[2].find('a').string)

	for url in urls:
#		decisor(url)
		onlyThug(url)


def threatLog(soup):
	logging.info("Fetching from Threat Log")
	table=soup.find('table', {'class':'table table-striped table-bordered'})
	rows=table.findAll('tr')
	urls=[]
	for row in rows:
		columns=row.findAll('td')
		url=''
		if len(columns)>=4:
			if columns[2].find('b'):
				url=columns[2].find('b').string
#				if columns[3].string!='-':
#					url=url+columns[3].string	#los paths acaban en '...'
				urls.append(url)

	for url in urls:
#		decisor(url)
		onlyThug(url)

#----------------------------------------------------------------------

if __name__ == "__main__":
    print "Malware Crawler v0.4"
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--thug", help="Enable thug analysis", action="store_true")
    parser.add_argument("-p", "--proxy", help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir", help="Define dump directory for retrieved files")
    parser.add_argument("-l", "--logfile", help="Define file for logging progress")
    args = parser.parse_args()

    try:
        if args.thug:
            loadthug()
    except:
        logging.warning("Thug analysis not enabled (use -t to enable thug)")

    # proxy support
    if args.proxy:
        proxy = urllib2.ProxyHandler({'http': args.proxy})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
        logging.info('Using proxy %s', args.proxy)
        my_ip = urllib2.urlopen('http://whatthehellismyip.com/?ipraw').read()
        logging.info('External sites see %s',my_ip)

    # dump directory
    # http://stackoverflow.com/questions/14574889/verify-directory-write-privileges
    if args.dumpdir:
        try:
            d = tempfile.mkdtemp(dir=args.dumpdir)
            dumpdir=args.dumpdir
        except Exception as e:
            logging.error('Could not open %s for writing (%s), using default', dumpdir, e)
            dumpdir = '/tmp/malware/unsorted'
        else:
            os.rmdir(d)
    else:
        dumpdir = '/tmp/malware/unsorted'

    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime) %message(s)', datefmt='%Y-%m-%d %H:%M:%S')

   #source list
    try:
        minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
    except:
        logging.error('Couldn\'t load Minotaur')
        pass

    try:
        malwaredl(parse('http://www.malwaredomainlist.com/hostslist/mdl.xml'))
    except:
        logging.error('Couldn\'t load Malware Domain List')
        pass

    try:
        vxvault(parse('http://vxvault.siri-urz.net/URL_List.php'))
    except:
        logging.error('Couldn\'t load VxVault')
        pass

    try:
        malc0de(parse('http://malc0de.com/rss'))
    except:
        logging.error('Couldn\'t load Malc0de')
        pass

    try:
        malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
    except:
        logging.error('Couldn\'t load Malware Black List')
        pass

    try:
        sacour(parse('http://www.sacour.cn/showmal.asp?month=%d&year=%d' % (now.month, now.year)))
    except:
        logging.error('Couldn\'t load Sacour')
        pass

    try:
        cleanMx(parse('http://support.clean-mx.de/clean-mx/viruses'))
    except:
        logging.error('Couldn\'t load Clean MX')
        pass

    try:
        spyEyeTracker(parse('https://spyeyetracker.abuse.ch/monitor.php?browse=binaries'))
    except:
        logging.error('Couldn\'t load SpyEyeTracker')
        pass

    try:
        zeusTracker(parse('https://zeustracker.abuse.ch/monitor.php?browse=binaries'))
    except:
        logging.error('Couldn\'t load ZeusTracker')
        pass

	#Solo thug
    try:
        mwisRu(parse('http://www.mwis.ru/'))
    except:
        logging.error('Couldn\'t load mwis.ru')
        pass

    try:
        threatLog(parse('http://www.threatlog.com/'))
    except:
        logging.error('Couldn\'t load Threat Log')
        pass
