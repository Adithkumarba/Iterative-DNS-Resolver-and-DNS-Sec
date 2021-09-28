import dns.rrset
import dns.query
import dns.dnssec
import dns.message
import ipaddress
import time
import datetime
import sys
import traceback as tb
from tabulate import tabulate

root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17','192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def cname_check(res, dtype):
  # check if the response contains a CNAME or an answer record
  if dtype == 'A':
    return (res.answer[0].rdtype == 1)
  if dtype == 'MX':
    return (res.answer[0].rdtype == 15 or res.answer[0].rdtype == 6)
  if dtype == 'NS':
    return (res.answer[0].rdtype == 2)

def checkSOA(rr):
  #check for SOA record
  if rr.to_text().split()[3] == 'SOA':
    return True
  return False

def resolve(host, cname_list ,dtype):
  for root in root_servers:
    try:
      query = dns.message.make_query(host, dtype)
      res = dns.query.udp(query, root, timeout=0.5)
      if len(res.additional) > 0:  
        while len(res.answer) == 0:
          #check for RR in additional section
          if len(res.additional) > 0:
            for rr in res.additional:

              #if its ipv6 record, skip
              if rr.to_text().split()[3] == 'AAAA':
                continue
              
              #extract ip from record
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
          #if additional section is empty check the authority section
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
          #if response contains CNAME, call resolve again with the CNAME as host
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

if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print('Wrong number of arguments')
        exit()

    s = time.time()
    web = str(sys.argv[1])
    dtype = str(sys.argv[2])
    canonicals = []
    res = resolve(web ,canonicals, dtype)
    ans_type = res.answer[0].to_text().split()[3]
    diff = time.time() - s
    print_o(web, res, ans_type, diff, canonicals)