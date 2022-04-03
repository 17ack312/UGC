import os,sys,nmap
import re ,datetime,json
#import subprocess

nm=nmap.PortScanner()
#python=sys.argv[2]

result={}
ports=[]
host=sys.argv[1]

def _scan(ip,arg):
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    for i in res.keys():
        res=res[i]
    return res

def set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,serv):
    vuln={}

    vuln['name'] = str(v_name)
    vuln['score'] = float(score)
    vuln['string'] = str(strng)
    vuln['risk'] = str(risk)
    vuln['desc'] = str(desc)
    vuln['imp'] = str(imp)
    vuln['sol'] = str(sol)
    vuln['ref'] = str(ref)
    vuln['link'] = str(link)
    vuln['port']=str(port)
    vuln['service']=str(serv)
    vuln['output']=str(script)

    return vuln

def process_data(data):
   for i in data.keys():
       if 'script' in (data[i].keys()) and str(data[i]['state'])=='open':
           port=str(i)
           ports.append(port)
           name=str(data[i]['name'])

           for j in (data[i]['script'].keys()):
              script=data[i]['script'][j]


              if str(j)=='dns-cache-snoop' and re.search('are cached',script,re.IGNORECASE):
                v_name='DNS Server Cache Snooping'
                score=5.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                risk='Medium'
                desc='The remote DNS server responds to queries for third-party domains that do not have the recursion bit set.'
                imp='This may allow a remote attacker to determine which domains have recently been resolved via this name server, and therefore which hosts have been recently visited.For instance, if an attacker was interested in whether your company utilizes the online services of a particular financial institution, they would be able to use this attack to build a statistical model regarding company usage of that financial institution. Of course, the attack can also be used to find B2B partners, web-surfing patterns, external mail servers, and more.\nNote: If this is an internal DNS server not accessible to outside networks, attacks would be limited to the internal network. This may include employees, consultants and potentially users on a guest network or WiFi connection if supported.'
                sol='Contact the vendor of the DNS software for a fix.'
                ref=''
                link='http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf'

                head=' [MED] DNS CACHE SNOOPING'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='dns-check-zone' and re.search('pass',script,re.IGNORECASE):
                
                v_name='DNS Server Zone Transfer Allowed'
                score=5.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                risk='Medium'
                desc='The remote DNS server allows zone transfers.'
                imp='A successful zone transfer was just observed. An attacker may use the zone information to discover sensitive information about hosts on your network.'
                sol='Verify that you only allow zone transfers to authorized hosts.'
                ref=''
                link='http://www.nessus.org/u?08f00b71'

                head=' [MED] DNS ZONE TRANSFER'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='dns-recursion' and re.search('enabled',script,re.IGNORECASE):
                
                v_name='DNS Server Recursion Enabled'
                score=5.0
                strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
                risk='Medium'
                desc='The remote DNS server allows zone transfers.'
                imp='If this is your internal nameserver, then the attack vector may be limited to employees or guest access if allowed.\nIf you are probing a remote nameserver, then it allows anyone to use it to resolve third party names.\nThis allows attackers to perform cache poisoning attacks against this nameserver.\nIf the host allows these recursive queries via UDP, then the host can be used to \'bounce\' Denial of Service attacks against another network or system'
                sol='Restrict recursive queries to the hosts that should use this nameserver (such as those of the LAN connected to it).If you are using bind 8, you can do this by using the instruction \'allow-recursion\' in the \'options\' section of your named.conf.If you are using bind 9, you can define a grouping of internal addresses using the \'acl\' command.Then, within the options block, you can explicitly state:\'allow-recursion { hosts_defined_in_acl }\'If you are using another name server, consult its documentation.'
                ref='CVE-1999-0024'
                link='http://www.nessus.org/u?c4dcf24a'

                head=' [MED] DNS RECURSION'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)



def _dns_enum():
    res=_scan(host,'-sV -sU --script=dns-cache-snoop.nse,dns-check-zone.nse,dns-recursion.nse --script-args="dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3},dns-check-zone.domain=example.com" -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_dns_enum()


res = sorted(result.items(), key = lambda x: x[1]['score'],reverse=True)

result={}
for i in res:
  x=i[0]
  y=dict(i[1])
  result[x]=y

#print(dict(result))


#or i in result:
#  print(result[i])

#result=(str(result).replace("'",'"'))

print(json.dumps(result))
