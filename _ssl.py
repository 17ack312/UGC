import os,sys,ctypes,nmap
import re,datetime
import subprocess

nm=nmap.PortScanner()
python=sys.argv[2]


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
               # 1
               if str(j)=='ssl-cert':
                   for x in (script).split('\n'):
                       if re.search('Not valid after',x):
                           s_date=(x.split(':',1)[1].split('T')[0].strip())
                           s_date=(datetime.datetime(int(s_date.split('-')[0]),int(s_date.split('-')[1]),int(s_date.split('-')[2])))

                           if s_date<datetime.datetime.now():
                               v_name='SSL Certificate Expiry'
                               score=5.3
                               strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                               risk='Medium'
                               desc="The remote server's SSL certificate has already expired."
                               imp="When you have an SSL certificate properly installed, your website’s server will engage in something called the SSL handshake anytime a visitor wants to make a connection. During this handshake, the user’s browser will be presented with the site’s SSL certificate. It needs to authenticate the certificate in order to complete the handshake.The authentication process requires the certificate to be within its validity dates. Every certificate has an issued and expired data coded into it. This allows the browser to determine whether it’s still valid or has expired. If the certificate is expired, the user’s browser has no way to validate the server. That means it can’t definitively tell you if the website presenting this certificate is its rightful owner.That’s going to cause a browser error that says your connection is not secure. The error is big; it blocks people from getting to your website – effectively breaking the site.Now, depending on how you’ve configured your server — all hope may not be lost. But you’d have to advise your customers to click through a browser warning, which most people aren’t going to do.However, if you’ve set up your website to use HTTP Strict Transport Security (HSTS), clicking through the warning won’t even be an option. HSTS forces secure connections, and if the certificate isn’t valid, the browser won’t be able to make one. In that case, your website is completely broken."
                               sol='Purchase or generate a new SSL certificate to replace the existing one.'
                               ref=''
                               link=''
                               head=' [MED] SSL CERTIFICATE EXPIRED'
                               result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
               #2
               if str(j)=='ssl-date':
                   ##DUE
                   pass
               #3
               if str(j)=='ssl-enum-ciphers':
                   if re.search('Weak certificate signature',script) or re.search('Insecure certificate signature',script):
                       v_name='SSL Certificate Signed Using Weak Hashing Algorithm'
                       score=7.5
                       strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'
                       risk='High'
                       desc='The remote service uses an  SSL certificate that has been signed using a cryptographically weak hashing  algorithm - MD2, MD4, or MD5. These signature algorithms are known to be  vulnerable to collision attacks.'
                       imp='In theory, a determined attacker may be  able to leverage this weakness to generate another certificate with the same  digital signature, which could allow him to masquerade as the affected  service.'
                       sol='Contact the Certificate Authority to have the SSL certificate reissued.'
                       ref='CVE-2004-2761,CERT:836068,CWE:310'
                       link='https://tools.ietf.org/html/rfc3279,http://www.nessus.org/u?9bb87bf2,http://www.nessus.org/u?e120eea1,http://www.nessus.org/u?5d894816,http://www.nessus.org/u?51db68aa,http://www.nessus.org/u?9dc7bfba'

                       head='[HIGH] SSL CERTIFICATE SIGNED WITH WEAK HASHING ALGORITHMS'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                   if re.search('vulnerable to SWEET32 attack',script):
                       v_name='SSL Medium Strength Cipher Suites Supported (SWEET32)'
                       score=7.5
                       strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                       risk='High'
                       desc='The remote service supports the use of medium strength SSL ciphers.'
                       imp='The remote host supports the use of SSL ciphers that offer medium strength encryption.Any encryption that uses key lengths at least 64 bits and less than 112 bits, or else that uses the 3DES encryption suite.'
                       sol = 'Reconfigure the affected application if possible to avoid use of medium strength ciphers.'
                       ref = 'CVE-2016-2183'
                       link = 'https://www.openssl.org/blog/blog/2016/08/24/sweet32/,https://sweet32.info'

                       head='[HIGH] SSL CIPHERS VULNERABLE TO SWEET32 ATTACK'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                   """
                   if re.search('Key exchange') and re.search('of lower strength than certificate key'):
                       v_name='SSL/TLS Diffie-Hellman Modulus'
                       score=3.7
                       strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'
                       risk='Low'
                       desc='The remote host allows SSL/TLS connections with one or more Diffie-Hellman moduli less than or equal to 1024 bits.'
                       imp='The remote host allows SSL/TLS connections with one or more Diffie-Hellman moduli less than or equal to 1024 bits. Through cryptanalysis, a third party may be able to find the shared secret in a short amount of time (depending on modulus size and attacker resources). This may allow an attacker to recover the plaintext or potentially violate the integrity of connections.'
                       sol='Reconfigure the service to use a unique Diffie-Hellman moduli of 2048 bits or greater.'
                       ref='CVE-2015-4000'
                       link='https://weakdh.org/'

                       head=' [LOW] SSL/TLS DIFFIE-HELLMAN MODULUS'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                   """

                   if re.search('Broken cipher RC4',script):
                       v_name='SSL RC4 Cipher Suites Supported'
                       score=5.9
                       strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                       risk='Medium'
                       desc='The remote service supports the use of the RC4 cipher.'
                       imp='The RC4 cipher is flawed in its generation of a pseudo-random stream of bytes so that a wide variety of small biases are introduced into the stream, decreasing its randomness.If plaintext is repeatedly encrypted (e.g., HTTP cookies), and an attacker is able to obtain many (i.e., tens of millions) ciphertexts, the attacker may be able to derive the plaintext.'
                       sol='Reconfigure the affected application, if possible, to avoid use of RC4 ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support.'
                       ref='CVE-2013-2566,CVE-2015-2808'
                       link='https://www.rc4nomore.com/,http://www.nessus.org/u?ac7327a0,http://cr.yp.to/talks/2013.03.12/slides.pdf,http://www.isg.rhul.ac.uk/tls/,https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf'

                       head=' [MED] SSL CIPHER CHAIN SUPPORTS RC4 CIPHERS WHICH IS DEPRECATED BY RFC 7465'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
               #4
               if str(j)=='sslv2-drown':
                   #if re.search('title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)',script) and \
                   if re.search('state: VULNERABLE',script):
                       v_name='SSL DROWN Attack Vulnerability'
                       score=5.9
                       strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                       risk='Medium'
                       desc='The remote host supports SSLv2 and therefore may be affected by a vulnerability that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption).'
                       imp="This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilizing previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key.The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a \"DROWN\" attack."
                       sol='Disable SSLv2 and export grade cryptography cipher suites. Ensure that private keys are not used anywhere with server software that supports SSLv2 connections.'
                       ref='CVE-2016-0800,CERT:583776'
                       link='https://drownattack.com/,https://drownattack.com/drown-attack-paper.pdf'

                       head=' [MED] SSL CIPHERS VULNERABLE TO DROWN ATTACK'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
               #5
               if str(j)=='ssl-ccs-injection':
                   if re.search('State: VULNERABLE',script):
                       v_name='SSL/TLS MITM vulnerability (CCS Injection)'
                       score=7.4
                       strng='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'
                       risk='High'
                       desc='The remote machine is affected by SSL CSS Injection vulnerability'
                       imp='OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the “CCS Injection” vulnerability.'
                       sol='http-openssl-0_9_8-upgrade-0_9_8_z_a\nhttp-openssl-1_0_0-upgrade-1_0_0_m\nhttp-openssl-1_0_1-upgrade-1_0_1_h'
                       ref='CVE-2014-0224'
                       link='https://attackerkb.com/topics/cve-2014-0224'

                       head='[HIGH] SSL/TLS MITM CSS INJECTION'
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

               #5
               if str(j)=='ssl-dh-params':
                   if re.search('State: VULNERABLE',script) and re.search('Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)',script):
                       v_name='Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)'
                       score=5.9
                       strng='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                       risk='Medium'
                       desc='The remote service is vulnerable to DHE_EXPORT Ciphers Downgrade MitM attack.'
                       imp='The Transport Layer Security (TLS) protocol contains a flaw that is triggered when handling DiffieHellman key exchanges defined with the DHE_EXPORT cipher. A man-in-the middle attacker may be able to downgrade the session to use EXPORT_DHE cipher suites. Thus, it is recommended to remove support for weak cipher suites.'
                       sol='Upgrade TLS certificate to fixed version'
                       ref='CVE-2015-4000'
                       link='https://www.securityfocus.com/bid/74733,https://weakdh.org'

                       head=' [Med] TLS DHE_EXPORT Ciphers Downgrade MitM (Logjam)'.upper()
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                   if re.search('State: VULNERABLE', script) and re.search('Diffie-Hellman Key Exchange Insufficient Diffie-Hellman Group Strength',script):
                       v_name='Diffie-Hellman Key Exchange Insufficient Diffie-Hellman Group Strength'
                       score=4.0
                       strng='CVSS:3.0/AV:N/AC:H/Au:N/C:P/I:P/A:N'
                       risk='Medium'
                       desc='The SSL/TLS service uses Diffie-Hellman groups with insufficient strength (key size < 2048).'
                       imp='The Diffie-Hellman group are some big numbers that are used as base for the DH computations. They can be, and often are, fixed. The security of the final secret depends on the size of these parameters. It was found that 512 and 768 bits to be weak, 1024 bits to be breakable by really powerful attackers like governments.An attacker might be able to decrypt the SSL/TLS communication offline.'
                       sol='Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use a 2048-bit or stronger Diffie-Hellman group (see the references). For Apache Web Servers: Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.'
                       ref=''
                       link='https://weakdh.org'

                       head=' [MED] SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability'.upper()
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                   if re.search('State: VULNERABLE', script) and re.search('Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters'):
                       v_name='Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters'
                       score=0
                       strng=''
                       risk='None'
                       desc=''
                       imp=''
                       sol=''
                       ref=''
                       link='https://weakdh.org'

                       head='[NONE] Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters'.upper()
                       result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

               #6
               if str(j)=='ssl-heartbleed':
                   if re.search('State: VULNERABLE', script):
                       v_name="OpenSSL 'Heartbleed' vulnerability"
                       score=7.5
                       strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                       risk='High'
                       desc='A vulnerability in OpenSSL could allow a remote attacker to expose sensitive data, possibly including user authentication credentials and secret keys, through incorrect memory handling in the TLS heartbeat extension.OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time. Note that an attacker can repeatedly leverage the vulnerability to retrieve as many 64k chunks of memory as are necessary to retrieve the intended secrets. The sensitive information that may be retrieved using this vulnerability include:\ni) Primary key material (secret keys)\nii)Secondary key material (user names and passwords used by vulnerable services)\niii)Protected content (sensitive data used by vulnerable services)\niv)Collateral (memory addresses and content that can be leveraged to bypass exploit mitigations)'
                       imp='This flaw allows a remote attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time.'
                       sol='OpenSSL 1.0.1g has been released to address this vulnerability.  Any keys generated with a vulnerable version of OpenSSL should be considered compromised and regenerated and deployed after the patch has been applied.'
                       ref='CVE-2014-0160'
                       link='https://www.kb.cert.org/vuls/id/720951,https://tools.ietf.org/html/rfc2409#section-8,https://heartbleed.com/'

                       head='[HIGH] VULNERABLE TO OPENSSL HEARTBLEED'
                       result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script,name)

               #7
               if str(j)=='ssl-poodle':
                   if re.search('State: VULNERABLE',script):
                       v_name='SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)'
                       score=6.8
                       strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N'
                       risk='Medium'
                       desc='It is possible to obtain sensitive information from the remote host with SSL/TLS-enabled services.'
                       imp='The remote host is affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode.MitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.As long as a client and service both support SSLv3, a connection can be \'rolled back\' to SSLv3, even if TLSv1 or newer is supported by the client and service.The TLS Fallback SCSV mechanism prevents \'version rollback\' attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism.This is a vulnerability in the SSLv3 specification, not in any particular SSL implementation. Disabling SSLv3 is the only way to completely mitigate the vulnerability.'
                       sol='Disable SSLv3.Services that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled.'
                       ref='CVE-2014-3566,CERT:577193'
                       link='https://www.imperialviolet.org/2014/10/14/poodle.html,https://www.openssl.org/~bodo/ssl-poodle.pdf.https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00'

                       head=' [MED] VULNERABLE TO SSL POODLE'
                       result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script,name)
   #print(result)

def _ssl_enum():
    res=_scan(host,'--script=ssl-enum-ciphers,ssl-ccs-injection.nse,ssl-cert-intaddr.nse,ssl-cert.nse,ssl-date.nse,ssl-dh-params.nse,ssl-known-key.nse,ssl-heartbleed.nse,ssl-poodle.nse,sslv2-drown.nse,sslv2.nse -F')

    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

def _sslyze():
    for port in ports:
        #comm=python+' -m sslyze '+str(host)+':'+str(i)+' --tlsv1 --sslv3 --tlsv1_3 --tlsv1_1 --reneg --compression --resum --openssl_ccs --sslv2 --heartbleed --certinfo --early_data --robot --elliptic_curves --fallback --tlsv1_2'
        comm='sslyze '+str(host)+':'+str(port)
        res=subprocess.check_output(comm,shell=True).decode()

        for x in res.replace('\r','').replace('\n','##').replace('*','#$*').split('#$'):
            if x.startswith('* Certificates Information:'):
                script=str(x).replace('##','\n')
                
                if re.search('Certificate does NOT match server hostname', x):
                    v_name = 'SSL Certificate with Wrong Hostname'
                    score = 5.3
                    strng = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                    risk = 'Medium'
                    desc = 'The SSL certificate for this service is for a different host.'
                    imp = 'The \'commonName\' (CN) attribute of the SSL certificate presented for this service is for a different machine.'
                    sol = 'Purchase or generate a proper SSL certificate for this service.'
                    ref = 'CWE-297'
                    link = 'https://help.ucybersolutions.com/index.php/2021/09/09/how-to-solve-ssl-certificate-with-wrong-hostname-error/'

                    head = ' [MED] SSL CERTIFICATE WITH WRONG HOSTNAME'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')

                if re.search('self signed certificate',x):
                    v_name='SSL Self-Signed Certificate'
                    score=6.8
                    strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N'
                    risk='Medium'
                    desc='The SSL certificate chain for this service ends in an unrecognized self-signed certificate.'
                    imp='The X.509 certificate chain for this service is not signed by a recognized certificate authority. If the remote host is a public host in production, this nullifies the use of SSL as anyone could establish a man-in-the-middle attack against the remote host.'
                    sol='Purchase or generate a proper SSL certificate for this service.'
                    ref='CVE-2020-15813'
                    link='https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/,'

                    head=' [MED] SSL/TLS SELF-SIGNED CERTIFICATE'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')

                if re.search('Certificate is NOT Trusted',x) or re.search('certificate untrusted',x):
                    v_name='SSL Certificate Cannot Be Trusted'
                    score=6.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
                    risk='Medium'
                    desc='The SSL certificate for this service cannot be trusted.'
                    imp='''The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below :\n- First, the top of the certificate chain sent by the server might not be descended from a known public certificate authority. This can occur either when the top of the chain is an unrecognized, self-signed certificate, or when intermediate certificates are missing that would connect the top of the certificate chain to a known public certificate authority.\n- Second, the certificate chain may contain a certificate that is not valid at the time of the scan. This can occur either when the scan occurs before one of the certificate's 'notBefore' dates, or after one of the certificate's 'notAfter' dates.\n- Third, the certificate chain may contain a signature that either didn't match the certificate's information or could not be verified. Bad signatures can be fixed by getting the certificate with the bad signature to be re-signed by its issuer. Signatures that could not be verified are the result of the certificate's issuer using a signing algorithm that Nessus either does not support or does not recognize.\nIf the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host.'''
                    sol='Purchase or generate a proper SSL certificate for this service.'
                    ref='CVE-2020-35733'
                    link='https://www.itu.int/rec/T-REC-X.509/en,https://en.wikipedia.org/wiki/X.509'

                    head = ' [MED] UNTRUSTED SSL/TLS CERTIFICATE'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')

            if x.startswith('* OpenSSL CCS Injection:'):
                if not re.search('Not vulnerable to OpenSSL CCS injection',x):
                    script=str(x).replace('#','\n')
                    v_name = 'SSL/TLS MITM vulnerability (CCS Injection)'
                    score = 7.4
                    strng = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'
                    risk = 'High'
                    desc = 'The remote machine is affected by SSL CSS Injection vulnerability'
                    imp = 'OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the “CCS Injection” vulnerability.'
                    sol = 'http-openssl-0_9_8-upgrade-0_9_8_z_a\nhttp-openssl-1_0_0-upgrade-1_0_0_m\nhttp-openssl-1_0_1-upgrade-1_0_1_h'
                    ref = 'CVE-2014-0224'
                    link = 'https://attackerkb.com/topics/cve-2014-0224'

                    head = '[HIGH] SSL/TLS MITM CSS INJECTION'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')

            if x.startswith('* OpenSSL Heartbleed:'):
                if not re.search('OK - Not vulnerable to Heartbleed',x):
                    script=str(x).replace('#','\n')
                    v_name = "OpenSSL 'Heartbleed' vulnerability"
                    score = 7.5
                    strng = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                    risk = 'High'
                    desc = 'A vulnerability in OpenSSL could allow a remote attacker to expose sensitive data, possibly including user authentication credentials and secret keys, through incorrect memory handling in the TLS heartbeat extension.OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time. Note that an attacker can repeatedly leverage the vulnerability to retrieve as many 64k chunks of memory as are necessary to retrieve the intended secrets. The sensitive information that may be retrieved using this vulnerability include:\ni) Primary key material (secret keys)\nii)Secondary key material (user names and passwords used by vulnerable services)\niii)Protected content (sensitive data used by vulnerable services)\niv)Collateral (memory addresses and content that can be leveraged to bypass exploit mitigations)'
                    imp = 'This flaw allows a remote attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time.'
                    sol = 'OpenSSL 1.0.1g has been released to address this vulnerability.  Any keys generated with a vulnerable version of OpenSSL should be considered compromised and regenerated and deployed after the patch has been applied.'
                    ref = 'CVE-2014-0160'
                    link = 'https://www.kb.cert.org/vuls/id/720951,https://tools.ietf.org/html/rfc2409#section-8,https://heartbleed.com/'

                    head = '[HIGH] VULNERABLE TO OPENSSL HEARTBLEED'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')

            if x.startswith('* Downgrade Attacks:'):
                if not re.search('OK - Supported',x):
                    script=str(x).replace('#','\n')
                    v_name = 'SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)'
                    score = 6.8
                    strng = 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N'
                    risk = 'Medium'
                    desc = 'It is possible to obtain sensitive information from the remote host with SSL/TLS-enabled services.'
                    imp = 'The remote host is affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode.MitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.As long as a client and service both support SSLv3, a connection can be \'rolled back\' to SSLv3, even if TLSv1 or newer is supported by the client and service.The TLS Fallback SCSV mechanism prevents \'version rollback\' attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism.This is a vulnerability in the SSLv3 specification, not in any particular SSL implementation. Disabling SSLv3 is the only way to completely mitigate the vulnerability.'
                    sol = 'Disable SSLv3.Services that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled.'
                    ref = 'CVE-2014-3566,CERT:577193'
                    link = 'https://www.imperialviolet.org/2014/10/14/poodle.html,https://www.openssl.org/~bodo/ssl-poodle.pdf.https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00'

                    head = ' [MED] VULNERABLE TO SSL POODLE'
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script, '')


_ssl_enum()
_sslyze()

print(result)
