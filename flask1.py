from datetime import datetime
import pygeoip as pygeoip
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template
import rfchkurl
import trial1
import trial2
from pythonping import ping
import whois
import mysql.connector
from urllib.parse import urlparse
import socket
import urllib.request
import dns.resolver
import urllib3

def getDomain(url):
    return urlparse(url).netloc

def getPath(url):
  try:
    return urlparse(url).path
  except:
      return None

def rank(url):
        try:
            r = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            r = int(r)
            return r
        except:
            return None

def getASN(url):
        try:
            host = urlparse(url).netloc
            g = pygeoip.GeoIP("E:\CIP\dataset-features\GeoIPASNum.dat")
            asn = int(g.org_by_name(host).split()[0][2:])
            return asn
        except:
            return None

def pingchk(url):
    val = ping(url, verbose=True)
    return val

def encdec(url,u):
  if u == "Encoder":
    encoded_query = urllib.parse.quote(url)
    return encoded_query
  else:
    decoded_query = urllib.parse.unquote(url)
    return decoded_query

app = Flask(__name__)

@app.route('/')
def login():
    return render_template('Home.html')

@app.route('/start')
def startproj():
    return render_template('Start.html')

@app.route('/whois')
def whois1():
    return render_template('Whos.html')

@app.route('/urled')
def urled1():
    return render_template('Urlencoderdecoder.html')

@app.route('/ping')
def ping1():
    return render_template('Ping.html')

@app.route('/his')
def his1():
    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="cip6134"
    )

    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM history ORDER BY S_no DESC LIMIT 5")

    myresult = mycursor.fetchall()
    y = []
    z = []
    for x in myresult:
        y.append(x[1])
        z.append(x[2])
        print(x[1],x[2])

    return render_template('History.html', u1=y[0], u2=y[1], u3=y[2], u4=y[3], u5=y[4],
                           f1=z[0], f2=z[1], f3=z[2], f4=z[3], f5=z[4])

@app.route('/scan', methods=['POST'])
def my_form_post():
    if request.method == 'POST':
       url = request.form['d']
       print(url)
       a = rfchkurl.pred(url)
       mydb = mysql.connector.connect(
           host="localhost",
           user="root",
           password="root",
           database="cip6134"
       )

       mycursor = mydb.cursor()

       sql = "INSERT INTO history(URL, RESULT) VALUES (%s, %s)"
       val = (url, a)
       mycursor.execute(sql, val)

       mydb.commit()

       print(mycursor.rowcount, "record inserted.")

       a1 = getDomain(url)
       a2 = rank(url)
       a3 = getASN(url)
       try:
        x = requests.get(url)
        a4 = x.status_code
        print(a4)
       except:
           a4=None
       try:
         http = urllib3.PoolManager()
         resp = http.request('HEAD', url)
         a6=resp.headers['Server']
       except:
         a6=None
       try:
         http = urllib3.PoolManager()
         resp = http.request('HEAD', url)
         a7=resp.headers['Content-Type']
       except:
         a7=None
       a5 = trial2.linksinurl(url)
       a8 = getPath(url)
       if a8 == None:
           a8=None
       return render_template('Scan.html', res=a, b1=a1, b2=a2, b3=a3, b4=a4, b5=a5, b6=a6, b7=a7, b8=a8)

@app.route('/check', methods=['POST'])
def my_form_post1():
    if request.method == 'POST':
       url = request.form['wh']
       print(url)
       s = trial1.is_registered(url)
       return render_template('Check.html', w1=s.registrar, w2=s.whois_server, w3=s.domain_name,
                              w4=s.creation_date, w5=s.expiration_date, w6=s.emails, w7=s.name_servers,
                              w8=s.org, w9=s.country, w10=s.state)

@app.route('/lookup', methods=['POST'])
def my_form_post2():
    if request.method == 'POST':
       url = request.form['p']
       print(url)
       v = pingchk(url)
       return render_template('Lookup.html', pingres=v)

@app.route('/submit', methods=['POST'])
def my_form_post3():
    if request.method == 'POST':
       url = request.form['ed']
       u = request.form['dropdown']
       print(url)
       print(u)
       v = encdec(url,u)
       return render_template('Submit.html', edres=v)

if __name__ == '__main__':
    app.run()
