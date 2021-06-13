from datetime import datetime

import whois


def age_domain(url):
  try:
    w = whois.whois(url)
    if(w):
        for l in w.expiration_date:
           d1 = datetime.date(l)
        print(d1)
        for l1 in w.creation_date:
           d2 = datetime.date(l1)
        print(d2)
        diff = (d1 - d2).days
        print(diff)
        if ((diff / 30) < 6):
            return 1
        else:
            return 0
  except:
      return -1

