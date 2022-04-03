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


              if str(j)=='ftp-anon' and re.search('login allowed',script,re.IGNORECASE):
                v_name='Anonymous FTP Login Enabled'
                score=5.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                risk='Medium'
                desc='Anonymous logins are allowed on the remote FTP server.'
                imp='The FTP server running on the remote host allows anonymous logins. Therefore, any remote user may connect and authenticate to the server without providing a password or unique credentials. This allows the user to access any files made available by the FTP server.'
                sol='Disable anonymous FTP if it is not required. Routinely check the FTP server to ensure that sensitive content is not being made available.'
                ref='CVE-1999-0497'
                link=''

                head=' [MED] ANONYMOUS FTP LOGIN'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='ftp-bounce' and re.search('bounce',script,re.IGNORECASE):
                v_name='FTP Bounce Attack'
                score=5
                strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
                risk='Medium'
                desc='The remote FTP server is prone to a denial of service attack.'
                imp='The NETFile FTP/Web server on the remote host is vulnerable to a denial of service attack due to its support of the FXP protocol and its failure to validate the IP address supplied in a PORT command.Additionally, this issue can be leveraged to bypass firewall rules to connect to arbitrary hosts.'
                sol='Upgrade to NETFile FTP/Web Server 7.6.0 or later and disable FXP support.'
                ref='CVE-2005-1646'
                link='http://www.security.org.sg/vuln/netfileftp746port.html'

                head=' [MED] FTP BOUNCE ATTACK'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='ftp-libopie' and re.search('vulnerable',script,re.IGNORECASE):
                v_name='OPIE off-by-one stack overflow'
                score=4.4
                strng='CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P'
                risk='Medium'
                desc='The remote host is missing one or more security-related updates.'
                imp='A programming error in the OPIE library could allow an off-by-one buffer overflow to write a single zero byte beyond the end of an on-stack buffer.'
                sol='Update the affected packages.'
                ref=''
                link='http://www.nessus.org/u?8197ddf8'

                head=' [MED] OPIE OFF_BY_ONE STACK-OVERFLOW'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='ftp-proftpd-backdoor' and re.search('backdoored',script,re.IGNORECASE):
                v_name='FTP Server Backdoor Detection'
                score=9.8
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                risk='Critical'
                desc='The remote FTP server has a backdoor.'
                imp='There is a backdoor in the old FTP daemons of Linux that allows remote users to log in as \'NULL\' with password \'NULL\'. These credentials provide root access.'
                sol='Upgrade your FTP server to the latest version.'
                ref='CVE-1999-0452'
                link='http://www.nessus.org/u?8197ddf8'

                head='[CRIT] FTP BACKDOOR DETECTION'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='ftp-vsftpd-backdoor' and re.search('vulnerable',script,re.IGNORECASE):
                v_name='vsFTPd version 2.3.4 backdoor'
                score=9.8
                strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                risk='Critical'
                desc='The remote FTP server has a backdoor.'
                imp='vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp'
                sol='Upgrade your FTP server to the latest version.'
                ref='CVE-2011-2523,CWE-78'
                link='http://www.nessus.org/u?8197ddf8'

                head='[CRIT] VSFTPD BACKDOOR DETECTION'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)












def _ftp_enum():
    res=_scan(host,'-sV --script=ftp-anon.nse,ftp-bounce.nse,ftp-libopie,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse --script-args="ftp-anon.maxlist=-1" -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_ftp_enum()


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
