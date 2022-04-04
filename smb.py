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


              if str(j)=='smb2-security-mode' and not re.search('Message signing enabled but not required',script,re.IGNORECASE):
                v_name='SMB Signing not required'
                score=5.3
                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                risk='Medium'
                desc='Signing is not required on the remote SMB server.'
                imp='Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.'
                sol='Enforce message signing in the host\'s configuration. On Windows, this is found in the policy setting \'Microsoft network server: Digitally sign communications (always)\'. On Samba, the setting is called \'server signing\'.'
                ref=''
                link='http://www.nessus.org/u?df39b8b3,http://technet.microsoft.com/en-us/library/cc731957.aspx,http://www.nessus.org/u?74b80723,https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html,http://www.nessus.org/u?a3cac4ea'

                head=' [MED] SMB SIGN-IN NOT REQUIRED'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb2-vuln-uptime' and not re.search('vulnerable',script,re.IGNORECASE):
                v_name='MS17-010: Security Update for Microsoft Windows SMB Server : ETERNALBLUE / ETERNALCHAMPION / ETERNALROMANCE / ETERNALSYNERGY / WannaCry / EternalRocks / Petya / uncredentialed check'
                score=8.1
                strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                risk='High'
                desc='The remote Windows host is affected by multiple vulnerabilities.'
                imp='The remote Windows host is affected by the following vulnerabilities :\n\t- Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted packet, to execute arbitrary code. (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0148)\n\t- An information disclosure vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests. An unauthenticated, remote attacker can exploit this, via a specially crafted packet, to disclose sensitive information. (CVE-2017-0147)\n\tETERNALBLUE, ETERNALCHAMPION, ETERNALROMANCE, and ETERNALSYNERGY are four of multiple Equation Group vulnerabilities and exploits disclosed on 2017/04/14 by a group known as the Shadow Brokers. WannaCry / WannaCrypt is a ransomware program utilizing the ETERNALBLUE exploit, and EternalRocks is a worm that utilizes seven Equation Group vulnerabilities. Petya is a ransomware program that first utilizes CVE-2017-0199, a vulnerability in Microsoft Office, and then spreads via ETERNALBLUE.'
                sol='Microsoft has released a set of patches for Windows Vista, 2008, 7, 2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. Microsoft has also released emergency patches for Windows operating systems that are no longer supported, including Windows XP, 2003, and 8.\nFor unsupported Windows operating systems, e.g. Windows XP, Microsoft recommends that users discontinue the use of SMBv1. SMBv1 lacks security features that were included in later SMB versions. SMBv1 can be disabled by following the vendor instructions provided in Microsoft KB2696547. Additionally, US-CERT recommends that users block SMB directly by blocking TCP port 445 on all network boundary devices. For SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary devices'
                ref='CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148'
                link='http://www.nessus.org/u?68fc8eff,http://www.nessus.org/u?321523eb,http://www.nessus.org/u?065561d0,http://www.nessus.org/u?d9f569cf,https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/,http://www.nessus.org/u?b9d9ebf9,http://www.nessus.org/u?8dcab5e4,http://www.nessus.org/u?234f8ef8,http://www.nessus.org/u?4c7e0cf3,https://github.com/stamparm/EternalRocks/,http://www.nessus.org/u?59db5b5b'

                head='[HIGH] MS17-010: SECURITY FOR MS WINDOWS SMB SERVER'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb-double-pulsar-backdoor' and not re.search('vulnerable',script,re.IGNORECASE):
                v_name='SMB Server DOUBLEPULSAR Backdoor / Implant Detection (EternalRocks)'
                score=8.1
                strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                risk='High'
                desc='A backdoor exists on the remote Windows host.'
                imp='DOUBLEPULSAR is one of multiple Equation Group SMB implants and backdoors disclosed on 2017/04/14 by a group known as the Shadow Brokers. The implant allows an unauthenticated, remote attacker to use SMB as a covert channel to exfiltrate data, launch remote commands, or execute arbitrary code.\nEternalRocks is a worm that propagates by utilizing DOUBLEPULSAR.'
                sol='Remove the DOUBLEPULSAR backdoor / implant and disable SMBv1.'
                ref='CVE-2017-0144'
                link='http://www.nessus.org/u?43ec89df,https://github.com/countercept/doublepulsar-detection-script,https://github.com/stamparm/EternalRocks/,http://www.nessus.org/u?68fc8eff'

                head='[HIGH] SMB DOUBLEPULSAR BACKDOOR'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb-os-discovery':
                pass
                ##DUE

              if str(j)=='smb-protocols' and re.search('SMBv1',script,re.IGNORECASE):
                v_name='Server Message Block (SMB) Protocol Version 1 Enabled'
                score=0.0
                strng=''
                risk='Informational'
                desc='The remote Windows host supports the SMBv1 protocol.'
                imp='The remote Windows host supports Server Message Block Protocol version 1 (SMBv1). Microsoft recommends that users discontinue the use of SMBv1 due to the lack of security features that were included in later SMB versions. Additionally, the Shadow Brokers group reportedly has an exploit that affects SMB; however, it is unknown if the exploit affects SMBv1 or another version. In response to this, US-CERT recommends that users disable SMBv1 per SMB best practices to mitigate these potential issues.'
                sol='Disable SMBv1 according to the vendor instructions in Microsoft KB2696547. Additionally, block SMB directly by blocking TCP port 445 on all network boundary devices. For SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary devices.'
                ref=''
                link='https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/,https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and,http://www.nessus.org/u?8dcab5e4,http://www.nessus.org/u?234f8ef8,http://www.nessus.org/u?4c7e0cf3'

                head='[INFO] SMBv1 ENABLED'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb-protocols' and re.search('SMBv1',script,re.IGNORECASE):
                v_name='Microsoft Windows SMBv1 Multiple Vulnerabilities'
                score=8.1
                strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                risk='High'
                desc='The remote Windows host supports the SMBv1 protocol.'
                imp='The remote Windows host has Microsoft Server Message Block 1.0 (SMBv1) enabled. It is, therefore, affected by multiple vulnerabilities :\n\t- Multiple information disclosure vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to disclose sensitive information. (CVE-2017-0267, CVE-2017-0268, CVE-2017-0270, CVE-2017-0271, CVE-2017-0274, CVE-2017-0275, CVE-2017-0276)\n\t- Multiple denial of service vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of requests. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMB request, to cause the system to stop responding. (CVE-2017-0269, CVE-2017-0273, CVE-2017-0280)\n\t- Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to execute arbitrary code. (CVE-2017-0272, CVE-2017-0277, CVE-2017-0278, CVE-2017-0279)'
                sol='Apply the applicable security update for your Windows version :\n\t- Windows Server 2008 : KB4018466\n\t- Windows 7 : KB4019264\n\t- Windows Server 2008 R2 : KB4019264\n\t- Windows Server 2012 : KB4019216\n\t- Windows 8.1 / RT 8.1. : KB4019215\n\t- Windows Server 2012 R2 : KB4019215\n\t- Windows 10 : KB4019474\n\t- Windows 10 Version 1511 : KB4019473\n\t- Windows 10 Version 1607 : KB4019472\n\t- Windows 10 Version 1703 : KB4016871\n\t- Windows Server 2016 : KB4019472'
                ref='CVE-2017-0267, CVE-2017-0268, CVE-2017-0269, CVE-2017-0270, CVE-2017-0271, CVE-2017-0272, CVE-2017-0273, CVE-2017-0274, CVE-2017-0275, CVE-2017-0276, CVE-2017-0277, CVE-2017-0278, CVE-2017-0279, CVE-2017-0280'
                link='http://www.nessus.org/u?c21268d4,http://www.nessus.org/u?b9253982,http://www.nessus.org/u?23802c83,http://www.nessus.org/u?8313bb60,http://www.nessus.org/u?7677c678,http://www.nessus.org/u?36da236c,http://www.nessus.org/u?0981b934,http://www.nessus.org/u?c88efefa,http://www.nessus.org/u?695bf5cc,http://www.nessus.org/u?459a1e8c,http://www.nessus.org/u?ea45bbc5,http://www.nessus.org/u?4195776a,http://www.nessus.org/u?fbf092cf,http://www.nessus.org/u?8c0cc566'

                head='[HIGH] SMBv1 MULTIPLE VULNERABILITY'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb-vuln-conficker' and re.search('VULNERABLE',script,re.IGNORECASE):
                v_name='Conficker Worm Detection (uncredentialed check)'
                score=10.0
                strng='CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
                risk='Critical'
                desc='The remote host seems to be infected by a variant of the Conficker worm.'
                imp='The remote host seems to be infected by the Conficker worm. This worm has several capabilities which allow an attacker to execute arbitrary code on the remote operating system. The remote host might also be attempting to propagate the worm to third party hosts.'
                sol='Update your Antivirus and perform a full scan of the remote operating system.'
                ref=''
                link='http://net.cs.uni-bonn.de/wg/cs/applications/containing-conficker/,https://support.microsoft.com/en-us/help/962007/virus-alert-about-the-win32-conficker-worm,http://www.nessus.org/u?1f3900d3'

                head='[CRIT] CONFICKER WORM DETECTED'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

              if str(j)=='smb-vuln-regsvc-dos' and re.search('VULNERABLE',script,re.IGNORECASE):
                v_name='Service regsvc in Microsoft Windows systems vulnerable to denial of service'
                score=7.8
                strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C'
                risk='High'
                desc='The remote Windows host has a denial of service vulnerability.'
                imp='A vulnerability in the SMB service on the remote Windows host can reportedly be abused by a remote, unauthenticated attacker to cause the host to stop responding until manually restarted.'
                sol='Microsoft has released a set of patches for Vista, 2008, 7, and 2008 R2.'
                ref='CVE-2011-1267'
                link='https://www.nessus.org/u?beda7c4d'

                head='[HIGH] SMB DOS VULNERABILITY'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)


              if str(j)=='smb-vuln-webexec' and re.search('VULNERABLE',script,re.IGNORECASE):
                v_name='Remote Code Execution vulnerability in WebExService'
                score=7.8
                strng='CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                risk='High'
                desc='A remote code execution vulnerability exists in WebExService (WebExec).'
                imp='A vulnerability in the update service of Cisco Webex Meetings Desktop App for Windows could allow an authenticated, local attacker to execute arbitrary commands as a privileged user. The vulnerability is due to insufficient validation of user-supplied parameters. An attacker could exploit this vulnerability by invoking the update service command with a crafted argument. An exploit could allow the attacker to run arbitrary commands with SYSTEM user privileges. While the CVSS Attack Vector metric denotes the requirement for an attacker to have local access, administrators should be aware that in Active Directory deployments, the vulnerability could be exploited remotely by leveraging the operating system remote management tools.'
                sol=''
                ref='CVE-2018-15442'
                link='http://www.securityfocus.com/bid/105734,http://www.securitytracker.com/id/1041942'

                head='[HIGH] SWEBEXSERVICE REMOTE CODE EXECUTION'
                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)



def _smb_enum():
    res=_scan(host,'-sV -sU -sS --script=smb2-security-mode.nse,smb-security-mode.nse,smb2-vuln-uptime.nse,smb-double-pulsar-backdoor.nse ,smb-os-discovery.nse,smb-protocols.nse,smb-vuln-conficker.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse,smb-vuln-webexec --script-args="smbusername=admin,smbpass=passowrd,webexec_gui_command=cmd,webexec_command=net user test test /add" -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_smb_enum()


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
