import dns.rrset
import dns.query
import dns.dnssec
import dns.message
import ipaddress
import time
import datetime
import dns.resolver
import sys
import traceback as tb
from tabulate import tabulate
import pandas as pd
import matplotlib.pyplot as plt

root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17','192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def cname_check(res, dtype):
  if dtype == 'A':
    return (res.answer[0].rdtype == 1)
  if dtype == 'MX':
    return (res.answer[0].rdtype == 15 or res.answer[0].rdtype == 6)
  if dtype == 'NS':
    return (res.answer[0].rdtype == 2)

def checkSOA(rr):
  if rr.to_text().split()[3] == 'SOA':
    return True
  return False

def resolve(host, cname_list ,dtype):
  for root in root_servers:
    try:
      query = dns.message.make_query(host, dtype)
      res = dns.query.udp(query, root, timeout=1)
      if len(res.additional) > 0:  
        while len(res.answer) == 0:
          if len(res.additional) > 0:
            for rr in res.additional:
              if rr.to_text().split()[3] == 'AAAA':
                continue
              
              ip = rr.to_text().split('\n')[0].split()[4]
              #print(ip)
              query = dns.message.make_query(host, dtype)
              try:
                new_res = dns.query.udp(query, ip, timeout=1)
                res = new_res
                break
              except Exception as ex:
                tb.print_exc()
          else:
            rr = res.authority[0]
            if checkSOA(rr):
                res.answer.append(rr)
                break
            
            name = res.authority[0][0].to_text()
            new_res = resolve(name, cname_list ,'A')
            x = new_res.answer[0]
            res.additional.append(x)
        if cname_check(res, dtype) == True:
          return res
        else:
          for rr in res.answer:
            cn = rr.to_text().split()[4]
            cname_list.append(cn)
            return resolve(cn,cname_list, dtype)
      break
    except Exception as ep:
      tb.print_exc()




def print_o(website, res, dtype, diff, cans):
  print("QUESTION SECTION:")
  print('{}\t\tIN\t{}\n\n'.format(website, dtype)) 
  print("ANSWER SECTION:")
  name = website
  ips = []
  alist = []
  for i in res.answer[0]:
    ips.append(str(i))
  for x in cans:
    alist.append([name,'IN','CNAME',x])
    name = x
  for ip in ips:
    alist.append([name,'IN',dtype,ip])
  msg_size = 0
  for l in alist:
    for s in l:
      msg_size += len(s) 
  print(tabulate(alist, tablefmt="plain"))
  print('\n')
  print('Query time: '+ str(int(diff*1000)) +  'msec')
  print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
  print('MSG SIZE rcvd: ', msg_size, '\n')

def calc_avg(website, dnsip):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dnsip]
    #print(resolver.nameservers)
    s = time.time()
    
    for i in range(10):
        res = dns.resolver.query(website, 'A')
    
    diff = time.time() - s
    return diff * 1000 /10

def measurement_metrics():
    websites = ['yahoo.com','Google.com', 'Youtube.com' , 'Facebook.com', 'Amazon.com', 'Wikipedia.org', 'Live.com','Zoom.us' , 'Tmall.com' ,'Linkedin.com', 'Myshopify.com', 'Ebay.com', 'Chase.com' ,'Office.com', 'Netflix.com', 'Reddit.com', 'Microsoft.com', 'Instagram.com', 'Chaturbate.com','Espn.com','Walmart.com' ,'Instructure.com','Bing.com', 'Twitter.com','Adobe.com']

    time_dict = {}
    for site in websites:
        avg_time = 0
        for i in range(10):
            time.sleep(1)
            s = time.time()
            dtype = 'A'
            canonicals = []
            res = resolve(site ,canonicals, dtype)
            diff = time.time() - s
            avg_time += int(diff * 1000)
        avg_time = avg_time/10
        print(site, avg_time)
        time_dict[site] = avg_time

    
    google_dns = {}
    for site in websites:
        google_dns[site] = calc_avg(site, '8.8.8.8')

    local_dns = {}
    for site in websites:
        local_dns[site] = calc_avg(website, '130.245.255.4')



    mydig_list = list(time_dict.values())

    s = pd.Series(mydig_list, name='time')

    df = pd.DataFrame(s)
    df['cdf'] = df.rank(method = 'average', pct = True)
    df = df.sort_values('time')

    df2 = pd.DataFrame.from_dict(google_dns, orient='index', columns=['time'])
    df2['cdf'] = df2.rank(method = 'average', pct = True)
    df2 = df2.sort_values('time')

    df3 = pd.DataFrame.from_dict(local_dns, orient='index', columns=['time'])
    df3['cdf'] = df3.rank(method = 'average', pct = True)
    df3 = df3.sort_values('time')

    plt.figure(figsize=(10,5))
    plt.plot(df2['time'], df2['cdf'], label='google')
    plt.plot(df['time'], df['cdf'], label='mydig dns')
    plt.plot(df3['time'], df3['cdf'], label='local dns')
    plt.xlabel("Time")
    plt.ylabel("cdf")
    plt.legend()
    plt.show()

if __name__ == "__main__":
    measurement_metrics()
