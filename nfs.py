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


              if str(j)=='nfs-showmount' and re.search('Telnet server supports encryption',script,re.IGNORECASE):
                v_name='NFS Share User Mountable'
                score=7.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                risk='High'
                desc='to access sensitive information from remote NFS shares without having root privileges.'
                imp='NFS shares exported by the remote server or disclose potentially sensitive information such as a directory listing. An attacker may exploit this issue to gain read and possibly write access to files on remote host, that root privileges were not required to mount the remote shares since the source port to mount the shares was higher than 1024.'
                sol='Configure NFS on the remote host so that only authorized hosts can mount the remote shares. The remote NFS server should prevent mount requests originating from a non-privileged port.'
                ref='CVE-1999-0554'
                link='https://support.datafabric.hpe.com/s/article/NFS-Security-Vulnerability-CVE-1999-0554?language=en_US'

                head=' [HIGH] NFS MOUNTABLE'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

  

def _nfs_enum():
    res=_scan(host,'-sV --script=nfs-showmount -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_nfs_enum()


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
