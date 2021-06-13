import pandas as pd
from urllib.parse import urlparse,urlencode
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib.request
import time
import socket
import pygeoip as pygeoip
from datetime import datetime

import t1
import t2
from t1 import domain_registration_length
from t2 import age_domain
from tld import get_tld

def tld(url):
      try:
        res = get_tld(url)
        return res
      except:
        return None

def httpchk(url):
        try:
            h = urlparse(url).scheme
            l = "http"
            if (h == l):
                return 1
            else:
                return 0
        except:
            return -1

def getProtocol(url):
        return urlparse(url).scheme

def getDomain(url):
        return urlparse(url).netloc

def getPath(url):
        return urlparse(url).path

def whois_Registrar(url):
      try:
        w = whois.whois(url)
        s = w.registrar
        return s
      except:
        return -1

def host_length(url):
        obj = urlparse(url)
        host = obj.netloc
        h = len(host)
        return h

def urlpath_length(url):
        p = urlparse(url).path
        h = len(p)
        return h

def tokens(url):
        if url == '':
            return 0
        token_word = re.split('\W+', url)
        # print token_word
        no_ele = 0
        for ele in token_word:
            l = len(ele)
            if l > 0:  ## for empty element exclusion in average length
                no_ele += 1
        return no_ele

def havingIP(url):
        """If the domain part has IP then it is phishing otherwise legitimate"""
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            # print match.group()
            return 1  # phishing
        else:
            # print 'No matching pattern found'
            return 0  # legitimate

def long_url(url):
        """This function is defined in order to differntiate website based on the length of the URL"""
        if len(url) <= 54:
            return 0  # legitimate
        elif len(url) > 54:
            return 1  # phishing
        else:
            return -1

def redirection(url):
        """If the url has symbol(//) after protocol then such URL is to be classified as phishing """
        if "//" in urlparse(url).path:
            return 1  # phishing
        else:
            return 0  # legitimate

def no_of_slash(url):
      try:
          c = urlparse(url).netloc
          b = urlparse(url).path
          d = c + b
          a = d.count('/')
          if a >= 5:
              return 1  # phishing
          else:
              return 0  # legitimate
      except:
          return -1

def no_of_hyphen(url):
      try:
        b = urlparse(url).netloc
        a = b.count('-')
        return a
      except:
          return -1

def no_of_specialchar(url):
       try:
           sc = re.findall(r"[-,.+#<>&!*;'=/}|_~:{\^@ %!?]", url)
           scl = len(sc)
           return scl
       except:
           return -1

def dots_in_url(url):
        """If the url has more than 3 dots then it is a phishing"""
        if url.count(".") <= 3:
            return 0  # legitimate
        elif url.count(".") > 3:
            return 1  # phishing

def shortening_service(url):
        """Tiny URL -> phishing otherwise legitimate"""
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          url)
        if match:
            return 1  # phishing
        else:
            return 0  # legitimate

def rank(url):
        try:
            r = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            r = int(r)
            if r > 100000:
                return 1  # phishing
            else:
                return 0  # legitimate

        except:
            return -1

def security_sensitive(url):
        tokens_words = re.split('\W+', url)
        sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin', 'online', 'check',
                         'verify', 'mail', 'install', 'toolbar', 'backup', 'paypal', 'PayPal', 'password','username', 'Sign',
                         'update', 'sign-in', 'banking']
        cnt = 0
        for ele in sec_sen_words:
            if (ele in tokens_words):
                cnt += 1;

        return cnt


def ssl(url):
        try:
            # Making a get request
            response = requests.get(url)
            if (response):
                return 0
            else:
                return -1
        except:
            return 1

def getASN(url):
        try:
            host = urlparse(url).netloc
            g = pygeoip.GeoIP("E:\CIP\dataset-features\GeoIPASNum.dat")
            asn = int(g.org_by_name(host).split()[0][2:])
            return asn
        except:
            return -1

def submitting_to_email(url):
        try:
            wiki = url
            reqs = requests.get(wiki)
            soup = BeautifulSoup(reqs.text, 'html.parser')
            for form in soup.find_all('form', action=True):
                if "mailto:" in form['action']:
                    return 1
                else:
                    return 0
        except:
            return -1

def i_frame(url):
        try:
            wiki = url
            reqs = requests.get(wiki)
            soup = BeautifulSoup(reqs.text, 'html.parser')
            for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
                # Even if one iFrame satisfies the below conditions, it is safe to return -1 for this method.
                if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
                    return 1
                if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
                    return 1
            # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
            return 0
        except:
            return -1

def links_in_tags(url):
        try:
            wiki = url
            domain = urlparse(wiki).netloc
            reqs = requests.get(wiki)
            soup = BeautifulSoup(reqs.text, 'html.parser')
            s = 0
            for link in soup.find_all('link', href=True):
                dots = [x.start() for x in re.finditer(r'\.', link['href'])]
                if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
                    s = s + 1

            for script in soup.find_all('script', src=True):
                dots = [x.start() for x in re.finditer(r'\.', script['src'])]
                if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
                    s = s + 1
            return s
        except:
            return -1

def url_of_anchor(url):
        try:
            wiki = url
            domain = urlparse(wiki).netloc
            reqs = requests.get(wiki)
            soup = BeautifulSoup(reqs.text, 'html.parser')
            s = 0
            for a in soup.find_all('a', href=True):
                # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
                # might not be
                # there in the actual a['href']
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        wiki in a['href'] or domain in a['href']):
                    s = s + 1
                # print a['href']
            return s
        except:
            return -1

def main(url):

 d=[[httpchk(url),rank(url),t1.domain_registration_length(url),t2.age_domain(url),ssl(url),havingIP(url),long_url(url),
     urlpath_length(url),host_length(url),tokens(url),no_of_specialchar(url),no_of_slash(url),no_of_hyphen(url),dots_in_url(url),
     security_sensitive(url),getASN(url),shortening_service(url),redirection(url),i_frame(url),
     links_in_tags(url),url_of_anchor(url)]]
 print(d)
 return d

#malicious-1
#safe-0
#Label,Httpchk,Rank,domain_registration_length,age_domain,ssl,Having_IP,URL_Length,urlpath_length,
# Host_Length,Tokens,No_of_specialchar,No_of_slash,No_of_hyphen,Dots_in_url,Security_sensitive,getASN,tiny_url,
# Redirection_//_symbol,i_frame,links_in_tags,url_of_anchor