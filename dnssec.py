# -*- coding: utf-8 -*-

import dns.rrset
import dns.query
import dns.dnssec
import dns.message
import ipaddress
import time
import datetime
import random
import sys
import cryptography
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
      res = dns.query.udp(query, root, timeout=0.2)
      if len(res.additional) > 0:  
        while len(res.answer) == 0:
          #check for RR in additional section
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


def dnssec(website, cans ,dtype):
    for root in root_servers:
        try:
            #Request for DNSKEY of root server
            query = dns.message.make_query(website, dtype, want_dnssec=True)
            res1 = dns.query.udp(query, root, timeout=1)
            query2 = dns.message.make_query('.', 'DNSKEY', want_dnssec=True)
            res1dns = dns.query.udp(query2, root, timeout=1)
            kskdns, rrsig, key_name = get_rr(res1dns , 'DNSKEY')
            
            try:
              dns.dnssec.validate(kskdns, rrsig, {key_name:kskdns})
            except Exception as e:
              tb.print_exc()

            rootkey_verify(kskdns)
            verify_record(res1, 'DS' ,key_name, kskdns)
            res2 = None
            res_dns2 = None
            if len(res1.additional) == 0:
                continue                           
            flag = 0
            while flag == 0:                            
                if len(res1.additional) > 0: 
                    #check if RR is there in additional section
                    rr = res1.authority[0]
                    next_site = rr.name.to_text()
                    for rr in res1.additional:
                        ip = rr.to_text().split(' ')[4]
                        try:
                            #request for DNSKEY to the TLD or Name servers
                            query = dns.message.make_query(website, dtype, want_dnssec=True)
                            res2 = dns.query.udp(query, ip, timeout=1)                          
                            query = dns.message.make_query(next_site, 'DNSKEY', want_dnssec=True)
                            res_dns2 = dns.query.udp(query, ip, timeout=1)                            
                            if len(res2.answer) != 0:
                                flag = 1
                                break

                            boolean = False
                            for rrset in res2.authority:
                                if rrset.rdtype == rtypes['DS']:
                                    boolean = True
                                    break
                            if boolean == False:
                                flag = 2
                                break
                            
                            kskdns, rrsig, key_name = get_rr(res_dns2, 'DNSKEY')
                            try:
                              #Validate RRSIG with KSK
                              dns.dnssec.validate(kskdns, rrsig, {key_name:kskdns})
                            except Exception as e:
                              tb.print_exc()
                            
                            #verify DS record of the next zone/server
                            verify_record(res2, 'DS', key_name, kskdns)

                            #verify current zone public KSK with the one obtained in the previous iteration
                            verify_parent_key(res_dns2, res1)
                            
                            res1 = res2
                            response_dnskey = res_dns2
                            break
                        except Exception as e:
                            tb.print_exc()
                            pass 
                else:             
                    name = res1.authority[0][0].to_text()
                    res2 = resolve(name, cans ,'A')
                    x = res2.answer[0]
                    res1.additional.append(x)
                   
            if flag == 2:
                return flag, res2
            
            if cname_check(res2, dtype): 
                try:
                    # if response does not contains CNAME
                    rr, rrsig_key, name = get_rr(res_dns2, 'DNSKEY')
                    dns.dnssec.validate(rr, rrsig_key, {name:rr})
                    verify_record(res2, 'A' ,name, rr)
                    verify_parent_key(res_dns2, res1)
                except Exception as e:
                    flag = 3
                    return flag, res2
                else:
                    return flag, res2
            else:                         
                for rrset in res1.answer:
                    cn = rr.to_text().split()[4]
                    cnames.append(cn)
                    return dnssec(cn, dtype, cnames)
            break
        except Exception as e:
            tb.print_exc()

def get_rr(res, rtype):
    #Extracts the RR , RRSIG and Name from response
    try:
        if rtype == 'NS' or rtype == 'DS':
          rsection = res.authority
        else:
          rsection = res.answer
        rr, rrsig, name = '', '', ''
        for rrset in rsection:  
            if rrset.rdtype == rtypes['RRSIG']:
                rrsig = rrset
            else:
                rr = rrset
                name = rrset.name
        return rr, rrsig, name

    except Exception as e:
        tb.print_exc()

def verify_record(res, rtype, name_key, dnskey):
    #validate DS / A record
    try:
        record, rrsig, name = get_rr(res, rtype)
        dns.dnssec.validate(record, rrsig, {name_key:dnskey})
    except Exception as e:
        raise e


def verify_parent_key(res, res_parent):
    #Validate public KSK of the zone with the one received in the previous iteration
    rr, rrsig, name = get_rr(res_parent, 'DS')
    parent_rr = rr[0]
    algorithm = 'SHA256' if parent_rr.digest_type ==2 else 'SHA1'
    pubksk = publicksk(res)
    ds = dns.dnssec.make_ds(name, pubksk, algorithm)
    
    if ds != parent_rr:
        raise Exception(' {} cannot be verified'.format(name.to_text()))

def publicksk(res):
    rr, rrsig_key, name = get_rr(res, 'DNSKEY')
    for item in rr:
        if item.flags == 257:
            return item


def rootkey_verify(keys):
    #verify the root keys by comparing with trust anchors
    for key in keys:
        if key.flags == 257:
            if key.to_text() == trust_anchors[0][0].to_text():
                continue
            elif key.to_text() == trust_anchors[1][0].to_text():
                continue
            else:
                raise Exception('Cannot be verified')


rtypes = {
    'A': 1      ,
    'NS':2      ,
    'DS':43     ,
    'RRSIG': 46 ,
    'DNSKEY':48 ,
}

trust_anchors = [
    #public KSK of root server
    dns.rrset.from_text('.', 1    , 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU='),
  
    dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0='),
]


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Wrong number of arguments. Expected 3, got {}'.format(len(sys.argv)))
    #website = 'dnssec-failed.org'
    #website = 'paypal.com'
    #website = 'cnn.com'

    website = str(sys.argv[1])
    dtype = str(sys.argv[2])
    canonicals = []

    s = time.time()

    flag, res = dnssec(website, canonicals, dtype)

    diff = time.time() - s

    if flag == 1:
        print('\nDNSSEC Verified\n')
        print_o( website, res, dtype, diff, canonicals)
    elif flag == 2:
        print('\nDNSSEC not supported for {}\n'.format(website))
    elif flag == 3:
        print('\nDNSSec Verification failed for {}\n'.format(website))    


