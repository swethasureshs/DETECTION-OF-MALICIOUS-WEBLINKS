from datetime import datetime

import whois

def domain_registration_length(url):
   try:
    w = whois.whois(url)
    for l in w.expiration_date:
        d1 = datetime.date(l)
    print(d1)
    d2 = datetime.date(datetime.now())
    print(d2)
    reg_length = 0
    if d1:
        reg_length = abs((d1 - d2).days)
    if ((reg_length / 365) <= 1):
        return 1  # phishing
    else:
        return 0  # legitimate
   except:
       return -1

