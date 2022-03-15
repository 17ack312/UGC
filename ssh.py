import os,sys,nmap
import re ,datetime,json
#import subprocess

nm=nmap.PortScanner()
#python=sys.argv[2]

result={}
ports=[]
host=sys.argv[1]

def _scan(ip, arg):
    res = nm.scan(hosts=ip, arguments=arg)['scan']
    #for i in res.keys():
    #    res = res[i]
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
               print(j)
               script=data[i]['script'][j]

               #1              
               if str(j)=='sshv1':
                if re.search('Server supports SSHv1',script,re.IGNORECASE):
                    v_name='SSH server supports SSH protocol v1 clients'
                    score=7.5
                    strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
                    risk='High'
                    desc='The SSH server support SSH version 1 clients. Version 1 of the SSH protocol contains fundamental weaknesses which make sessions vulnerable to man-in-the-middle attacks.'
                    imp='The SSH-1 protocol allows remote servers conduct man-in-the-middle attacks and replay a client challenge response to a target server by creating a Session ID that matches the Session ID of the target, but which uses a public key pair that is weaker than the target\'s public key, which allows the attacker to compute the corresponding private key and use the target\'s Session ID with the compromised key pair to masquerade as the target.'
                    sol='ssh-require-protocol-version-2'
                    ref='CVE-2001-1473,CWE:310'
                    link='http://www.kb.cert.org/vuls/id/684820,https://exchange.xforce.ibmcloud.com/vulnerabilities/6603'

                    head='[HIGH] SSH V1 is SUPPORTED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                

               #2
               if str(j)=='ssh2-enum-algos':
                for x in (script.replace('\r','').strip().replace('\n','#').replace('kex_algorithms:','\nkex_algorithms:').replace('server_host_key_algorithms:','\nserver_host_key_algorithms:').replace('encryption_algorithms:','\nencryption_algorithms:').replace('mac_algorithms:','\nmac_algorithms:').replace('compression_algorithms:','\ncompression_algorithms:')).split('\n'):
                    if re.search('encryption_algorithms:',x,re.IGNORECASE) and (re.search('arcfour',x,re.IGNORECASE)):
                        v_name='SSH Weak Algorithms Supported'
                        score=4.3
                        strng='CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N'
                        risk='Medium'
                        desc='The remote SSH server is configured to allow weak encryption algorithms or no algorithm at all.'
                        imp='The server supports one or more weak key exchange algorithms. It is highly adviseable to remove weak key exchange algorithm support from SSH configuration files on hosts to prevent them from being used to establish connections.'
                        sol='To disable SSH weak algorithms supported in Linux you need to Disable SSH Server Weak and CBC Mode Ciphers and SSH Weak MAC Algorithms. Follow the articles given below to disable ssh weak algorithms support in a Linux server.\ni) Disable SSH Server Weak and CBC Mode Ciphers in Linux.\nii) Disable SSH Weak MAC Algorithms in Linux'
                        ref=''
                        link='https://tools.ietf.org/html/rfc4253#section-6.3'

                        head=' [MED] SSH WEAK ALGORITHM SUPPORTED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('encryption_algorithms:',x,re.IGNORECASE) and (re.search('cbc',x,re.IGNORECASE)):
                        v_name='SSH Server CBC Mode Ciphers Enabled'
                        score=2.6
                        strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                        risk='Low'
                        desc='The SSH server is configured to use Cipher Block Chaining.'
                        imp='The SSH server is configured to support Cipher Block Chaining (CBC) encryption. This may allow an attacker to recover the plaintext message from the ciphertext.'
                        sol='Contact the vendor or consult product documentation to disable CBC mode cipher encryption, and enable CTR or GCM cipher mode encryption.'
                        ref='CVE-2008-5161,CWE:200,CERT:958563'
                        link=''

                        head=' [LOW] SSH CBC MODE CIPHERS ENABLED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('mac_algorithms:',x,re.IGNORECASE) and (re.search('hmac',x,re.IGNORECASE)):
                        v_name='SSH Weak MAC Algorithms Enabled'
                        score=2.6
                        strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                        risk='Low'
                        desc='The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.'
                        imp='The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.'
                        sol='Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.'
                        ref='CVE-2008-5161'
                        link='https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/'

                        head=' [LOW] SSH WEAK MAC ALGORITHM DETECTED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('kex_algorithms:',x,re.IGNORECASE) and (re.search('-sha1',x,re.IGNORECASE) or re.search('non-elliptic-curve',x,re.IGNORECASE) or re.search('rsa1024',x,re.IGNORECASE)):
                        v_name='SSH Weak MAC Algorithms Enabled'
                        score=2.6
                        strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                        risk='Low'
                        desc='The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.'
                        imp='The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.'
                        sol='Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.'
                        ref='CVE-2008-5161'
                        link='https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/'

                        head=' [LOW] SSH WEAK MAC ALGORITHM DETECTED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
  
               #3
               if str(j)=='ssh-brute':
                    #print(script)
                    pass

               #4
               if str(j)=='ssh-hostkey':
                    #print(script)
                    pass


    

def ssh_nm():
    res=_scan(host,'--script=sshv1.nse,ssh2-enum-algos.nse,ssh-brute.nse,ssh-hostkey.nse --script-args="userdb=users.lst, passdb=pass.lst, ssh-brute.timeout=4s,ssh_hostkey=all, ssh-run.cmd=ls , ssh-run.username=admin, ssh-run.password=password" -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)


ssh_nm()

print(json.dumps(result))
