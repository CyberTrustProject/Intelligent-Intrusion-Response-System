import urllib3
import urllib.request
import json
import wget
import re
import requests
import html
from os import listdir
from os.path import isfile, join
import zipfile
import os

from bs4 import BeautifulSoup

url = "https://nvd.nist.gov/vuln/data-feeds"

fp = urllib.request.urlopen(url)
mybytes = fp.read()
mystr = mybytes.decode("utf8")
fp.close()

soup = BeautifulSoup(mystr, features="html.parser")
soup.prettify()

totLinksList = []
zipLinks = []

for link in soup.find_all('a'):
    totLinksList.append(link.get('href'))

for link in totLinksList:
    if link is not None:
        check = "json.zip"
        if check in link:
           zipLinks.append(link)


del zipLinks[:2]
del zipLinks[-1]
print(zipLinks)
version = " "
name0 = "https://nvd.nist.gov/feeds/json/cve/"
name1 = version + "/"
name2 = ".json.zip"

path = "json"

try:
    os.mkdir(path)
except OSError:
    print("Creation of the directory %s failed" % path)
else:
    print(" [CREATING DIR] Successfully created the directory %s " % path)


print(' [DOWNLOAD] Beginning zips download')
for link in zipLinks:

    r_file = requests.get(link, stream=True)
    with open("json/" + link.replace('https://nvd.nist.gov/feeds/json/cve/1.1/', ''), 'wb') as f:
        for chunk in r_file:
            f.write(chunk)

files = [f for f in listdir("json/") if isfile(join("json/", f))]
files.sort()
print(files)

for file in files:
    print(' [EXTRACTING]' + file)
    with zipfile.ZipFile('json/' + file, 'r') as zip_ref:
        zip_ref.extractall('json/')

for link in zipLinks:
    print(' [DELETING]' + link)
    os.remove("json/" + link.replace('https://nvd.nist.gov/feeds/json/cve/1.1/', ''))
