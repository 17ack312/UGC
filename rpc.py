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

              if str(j)=='realvnc-auth-bypass' and re.search('VULNERABLE',script,re.IGNORECASE):
                v_name='RealVNC 4.1.0 - 4.1.1 Authentication Bypass'
                score=7.5
                strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
                risk='High'
                desc='RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP, allows remote attackers to bypass authentication via a request in which the client specifies an insecure security type such as "Type 1 - None", which is accepted even if it is not offered by the server, as originally demonstrated using a long password.'
                imp='RealVNC is susceptible to an authentication-bypass vulnerability. A malicious VNC client can cause a VNC server to allow it to connect without any authentication regardless of the authentication settings configured in the server. Exploiting this issue allows attackers to gain unauthenticated, remote access to the VNC servers.'
                sol='Update the affected package.'
                ref='CVE-2006-2369,CWE-287'
                link='http://www.intelliadmin.com/index.php/2006/05/security-flaw-in-realvnc-411/,https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2369'

                head='[HIGH] RealVNC AUTH BYPASS'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='rdp-vuln-ms12-020' and re.search('VULNERABLE',script,re.IGNORECASE):
                if re.search('Denial Of Service',script,re.IGNORECASE):
                  
                  v_name='MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability'
                  score=4.2
                  strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P'
                  risk='Medium'
                  desc='Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.'
                  imp='A DDoS attack means that it is administered with the same target from different sources – and here the Internet of Things must feel for hackers a bit like a toyshop would to children: millions of devices, all too often unprotected and unmonitored for long periods of time. The scale in which these attacks are now possible is rising tremendously with the advancement of the Internet of Things.'
                  sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                  ref='CVE-2012-0152'
                  link='http://technet.microsoft.com/en-us/security/bulletin/ms12-020,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-015'

                  head=' [MED] RDP DOS ATTACK (MS12-020)'
                  result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                  
                if re.search('Remote Code Execution',script,re.IGNORECASE):
                  v_name='MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability'
                  score=4.2
                  strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P'
                  risk='Medium'
                  desc='Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.'
                  imp='An arbitrary remote code vulnerability exists in the implementation of the Remote Desktop Protocol (RDP) on the remote Windows host. The vulnerability is due to the way that RDP accesses an object in memory that has been improperly initialized or has been deleted.If RDP has been enabled on the affected system, an unauthenticated, remote attacker could leverage this vulnerability to cause the system to execute arbitrary code by sending a sequence of specially crafted RDP packets to it.'
                  sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                  ref='CVE-2012-0002'
                  link='http://technet.microsoft.com/en-us/security/bulletin/ms12-020,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002'

                  head=' [MED] RDP RCE ATTACK (MS12-020)'
                  result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)




def _rpc_enum():
    res=_scan(host,'-sV --script=realvnc-auth-bypass.nse,rdp-vuln-ms12-020.nse -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_rpc_enum()


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
