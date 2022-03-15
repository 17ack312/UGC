import json,re,sys,os
import requests

url = "https://log4j-vulnerability-tester.p.rapidapi.com/v1/test"

#host='vckolkata63.org'

host=sys.argv[1]
result={}


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

if not(host.startswith('http')):
    host='http://'+host

#print(host)
querystring = {"url":host}

headers = {
    'x-rapidapi-host': "log4j-vulnerability-tester.p.rapidapi.com",
    'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"
    }

response = requests.request("GET", url, headers=headers, params=querystring)

res=json.loads(response.text)

try:
	x=str(res["vulnerabilities"]['cve_2021_44228'])
except:
	x='False'

if x=='True':
	v_name='Apache Log4j 1.x Multiple Vulnerabilities'
	score=9.8
	strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
	risk='Critical'
	desc='Log4j is a powerful logging facility used to monitor and track system calls in web servers (and other tools) to log activities. The Log4j code is created by an open-source project managed by the Apache Software Foundation.The code is deeply embedded in systems and tools that we all use every day. It is as ubiquitous as it is obscure. While you may have never heard of it until December 2021, it has been – and will continue to be – used by millions of web servers, gaming platforms and other services on the internet. It is found in Apache Tomcat web servers, the Minecraft gaming platform, Apple iCloud, Amazon Web Services (AWS) and beyond.Organizations that use Apache Tomcat include millions of people. We’re talking about virtually every government, large company and small business in every vertical market. Major banks and manufacturers use services that employ Log4j day in and day out. It represents a major attack surface, with implications across every sector, from finance to the manufacturing supply chain.\nThe Logj4 vulnerability is a highly significant event. It is a serious vulnerability and threat spawning real exploit software and leading to actual security incidents. But it’s significant for two more reasons, as it is:\n\t1.The first major instigator of security alert fatigue.\n\t2.An opportunity for the IT and developer community to make a few changes.'
	imp='According to its self-reported version number, the installation of Apache Log4j on the remote host is 1.x and is no longer supported. Log4j reached its end of life prior to 2016. Additionally, Log4j 1.x is affected by multiple vulnerabilities, including :\n- Log4j includes a SocketServer that accepts serialized log events and deserializes them without verifying whether the objects are allowed or not. This can provide an attack vector that can be exploited. (CVE-2019-17571)\n- Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. (CVE-2020-9488)\n- JMSSink uses JNDI in an unprotected manner allowing any application using the JMSSink to be vulnerable if it is configured to reference an untrusted site or if the site referenced can be accesseed by the attacker.(CVE-2022-23302)\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.'
	sol='Upgrade to a version of Apache Log4j that is currently supported.Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate versions / patches have known high severity vulnerabilities and the vendor is updating their advisories often as new research and knowledge about the impact of Log4j is discovered.'
	ref='CVE-2019-17571,CVE-2020-9488,CVE-2022-23302,CVE-2022-23305,CVE-2022-23307,CWE:502'
	link='https://logging.apache.org/log4j/1.2/'

	head='[CRITC] APACHE LOG4J VULNERABILITY'


	result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

print(json.dumps(result))
