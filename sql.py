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


              if str(j)=='ms-sql-empty-password' and re.search('success',script,re.IGNORECASE):
                v_name='MySQL Unpassworded Account Check'
                score=7.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                risk='High'
                desc='The remote database server can be accessed without a password.'
                imp='It is possible to connect to the remote MySQL database server using an unpassworded account. This may allow an attacker to launch further attacks against the database.'
                sol='Disable or set a password for the affected account.'
                ref='CVE-2002-1809, CVE-2004-1532'
                link='https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html'

                head='[HIGH] MYSQL UNCREDENTIAL CHECK'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='mysql-empty-password' and re.search('has empty password',script,re.IGNORECASE):
                v_name='MySQL Unpassworded Account Check'
                score=7.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                risk='High'
                desc='The remote database server can be accessed without a password.'
                imp='It is possible to connect to the remote MySQL database server using an unpassworded account. This may allow an attacker to launch further attacks against the database.'
                sol='Disable or set a password for the affected account.'
                ref='CVE-2002-1809, CVE-2004-1532'
                link='https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html'

                head='[HIGH] MYSQL UNCREDENTIAL CHECK'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='ms-sql-xp-cmdshell' and re.search('output',script,re.IGNORECASE):
                v_name='MS12-048: Vulnerability in Windows Shell Could Allow Remote Code Execution'
                score=9.3
                strng='CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C'
                risk='High'
                desc='A remote code execution vulnerability exists in the way Windows handles file and directory names.'
                imp='By tricking a user into opening a file or directory with a specially crafted name, an attacker could exploit this vulnerability to execute arbitrary code on the remote host subject to the privileges of the user.'
                sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                ref='CVE-2012-0175'
                link='https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-048'

                head='[HIGH] MS12-048:MS-SQL RCE'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)




def _sql_enum():
  
  res=_scan(host,'-sV --script=ms-sql-empty-password.nse,mysql-empty-password.nse,ms-sql-xp-cmdshell.nse,ms-sql-hasdbaccess.nse  --script-args="mssql.instance-all,mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd=ipconfig" -F')

  if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
  if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_sql_enum()


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
