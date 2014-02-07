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
# - BeautifulSoup 3.0.8 (Upgraded to BeautifulSoup 4 )

from bs4 import BeautifulSoup as bs

import sys
import hashlib
import re
import urllib2
import magic
import os
import socket
import datetime

UNSORTED_FOLDER = '/opt/malware/unsorted'
HTTP_TIMEOUT = 15
THUG_PATH = '/opt/thug/src'

# By default thug analyis is disabled
isthug = False

# variable for date value manipulation
now = datetime.datetime.now()
str(now)

# maximum wait time of http gets
socket.setdefaulttimeout(HTTP_TIMEOUT)

# load thug function, also checks if thug is installed
def loadthug():
    try:
        sys.path.append(THUG_PATH)
        import thug

        isthug = True
        print "- Thug module loaded for html analysis"
    except ImportError:
        print "- No Thug module found, html code inspection won't be available"

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
        http = bs(urllib2.urlopen(request))
    except:
        print "- Error parsing %s" % (url)
        return
    return http


def decisor(url):
    if not re.match('http', url):
        url = 'http://' + url

    try:
        url_dl = urllib2.urlopen(url).read()
    except Exception, e:
        #print "-- Error: %s" % e
        return

    filetype = gettype(url_dl).split(' ')[0]
    md5 = hashlib.md5(url_dl).hexdigest()

    if (filetype == 'HTML'):
        if isthug:
            print "-- Thug candidate: HTML code in %s" % url

            try:
                thug.Thug([url])()
            except Exception, e:
                print "- Thug error: %s" % e
                return

    else:
        dest = UNSORTED_FOLDER + filetype
        fpath = dest + '/' + str(md5)

        if not os.path.exists(dest):
            os.makedirs(dest)

        if not os.path.exists(fpath):
            file = open(fpath, 'wb')
            file.write(url_dl)
            file.close
            print "\t\t [*] Saved file type %s with md5: %s" % (filetype, md5)

# Process links from MalwareDomainList
#
# Modified for better performance and clarity ------------------------------------------------------------------
def malwaredl(soup):
    print "[+] Fetching from Malware Domain List"
    mdl_sites = []
    for i in soup.find_all('item'):
        site_url = (i.description.string).split()[1].replace(',', '')

        if site_url != '-':
            mdl_sites.append(site_url)
        else:
            mdl_sites.append((i.description.string).split()[4].replace(',', ''))

    print "\t [+] Found %s urls" % len(mdl_sites)
    for row in mdl_sites:
        decisor(row)

# Process links from VXVault
#
# Modified for better performance and clarity ------------------------------------------------------------------
def vxvault(soup):
    print "[+] Fetching from VXVault"
    vxv = []
    for row in soup('pre'):
        vxv = row.string.split('\n')
    vxv = vxv[4:]
    print "\t [+] Found %s urls" % len(vxv)
    for row in vxv:
        decisor(row)

# Process links from Malc0de
#
# Modified for better performance and clarity ------------------------------------------------------------------
def malc0de(soup):
    print "[+] Fetching from MalC0de List"
    mlc_sites = []
    for i in soup.find_all('item'):
        site_url = "http://" + re.sub('&amp;', '&', i.description.string.split()[1]).replace(',', '')
        mlc_sites.append(site_url)

    print "\t [+] Found %s urls" % len(mlc_sites)
    for row in mlc_sites:
        decisor(row)

# Process links from Malware Black List
#
# Modified for better performance and clarity ------------------------------------------------------------------
def malwarebl(soup):
    print "- Fetching from Malware Black List"
    mbl_sites = []

    for i in soup.find_all('item'):
        site_url = "http://" + re.sub('&amp;', '&', i.description.string.split()[1]).replace(',', '')
        mbl_sites.append(site_url)

    print "\t [+] Found %s urls" % len(mbl_sites)
    for row in mbl_sites:
        decisor(row)


def minotaur(soup):
    print "- Fetching from NovCon Minotaur"
    min = []
    for row in soup('td'):
        try:
            if re.match('http', row.string):
                min.append(row.string)
        except:
            pass
    print "-- Found %s urls" % len(min)
    for row in min:
        decisor(row)


def sacour(soup):
    print "- Fetching from Sacour.cn"
    for url in soup('a'):
        min = []
        if re.match('list/', url['href']):
            suburl = parse('http://www.sacour.cn/' + url['href'])
            for text in suburl('body'):
                for urls in text.contents:
                    if re.match('http://', str(urls)):
                        min.append(str(urls))
        if len(min) > 0:
            print "-- Found %s urls in %s" % (len(min), url['href'])
            for row in min:
                decisor(row)


if __name__ == "__main__":
    print "Malware Parser v0.4"

    try:
        if sys.argv[1] == '-t':
            loadthug()
    except:
        print "- Thug analysis not enabled (use -t to enable thug)"

    #source list
    try:
        minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
    except:
        print "[ERROR] Unexpected error processing Minotaur List"

    try:
        malwaredl(parse('http://www.malwaredomainlist.com/hostslist/mdl.xml'))
    except:
        print "[ERROR] Unexpected error processing Malware Domain List"

    try:
        vxvault(parse('http://vxvault.siri-urz.net/URL_List.php'))
    except:
        print "[ERROR] Unexpected error processing VXVault List"

    try:
        malc0de(parse('http://malc0de.com/rss'))
    except:
        print "[ERROR] Unexpected error processing Malc0de List"

    try:
        malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
    except:
        print "[ERROR] Unexpected error processing Malware Black List"

    try:
        sacour(parse('http://www.sacour.cn/showmal.asp?month=%d&year=%d' % (now.month, now.year)))
    except:
        print "[ERROR] Unexpected error processing Sacour List"
