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

              if str(j)=='smtp-brute':
                pass
                ##DUE

              if str(j)=='smtp-commands' and re.search('Commands supported',script,re.IGNORECASE):
                if re.search('STARTTLS',script,re.IGNORECASE):
                  v_name='SMTP Service Supports STARTTLS Command'
                  score=0.0
                  strng=''
                  risk='Informational'
                  desc='The remote SMTP service supports the use of the \'STARTTLS\' command to switch from a cleartext to an encrypted communications channel.'
                  imp='N/A'
                  sol='N/A'
                  ref=''
                  link='https://en.wikipedia.org/wiki/STARTTLS,https://tools.ietf.org/html/rfc2487'

                  head='[INFO] SMTP SERVICE SUPPORT STARTTLS COMMAND'
                  result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smtp-open-relay' and re.search('Server is an open relay',script,re.IGNORECASE):
                v_name='MTA Open Mail Relaying Allowed'
                score=7.5
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
                risk='High'
                desc='An open SMTP relay is running on the remote host.'
                imp='This issue allows any spammer to use your mail server to send their mail to the world, thus flooding your network bandwidth and possibly getting your mail server blacklisted.'
                sol='Reconfigure your SMTP server so that it cannot be used as an indiscriminate SMTP relay. Make sure that the server uses appropriate access controls to limit the extent to which relaying is possible.'
                ref='CVE-1999-0512'
                link='https://en.wikipedia.org/wiki/Email_spam'

                head='[HIGH] MTA OPEN RELAYING ENABLED'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smtp-strangeport' and re.search('Mail server on unusual port',script,re.IGNORECASE):
                pass
                ##DUE







def _smpt_enum():
    res=_scan(host,'--script=smtp-brute.nse,smtp-commands.nse,smtp-strangeport.nse,smtp-open-relay.nse --script-args="smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1"  -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_smpt_enum()


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
