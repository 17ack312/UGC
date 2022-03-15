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

                #print("==============================================================================")
                #print(j,script)

                if str(j)=='http-apache-negotiation' and re.search('mod_negotiation enabled',script,re.IGNORECASE):
                    v_name='Apache mod_negotiation Multiple Vulnerabilities'
                    score=5.3
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='mod_negotiation is an Apache module responsible for selecting the document that best matches the clients capabilities, from one of several available documents. If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error containing a pseudo directory listing. This behaviour can help an attacker to learn more about his target, for example, generate a list of base names, generate a list of interesting extensions, look for backup files and so on.'
                    imp='Multiple vulnerabilities have been found in Apache mod_negotiation: * Cross-site scripting (XSS) vulnerability in the mod_negotiation module in the Apache HTTP Server 2.2.6 and earlier in the 2.2.x series, 2.0.61 and earlier in the 2.0.x series, and 1.3.39 and earlier in the 1.3.x series allows remote authenticated users to inject arbitrary web script or HTML by uploading a file with a name containing XSS sequences and a file extension, which leads to injection within a \'406 Not Acceptable\' or \'300 Multiple Choices\' HTTP response when the extension is omitted in a request for the file.\n i) ap_get_basic_auth_pw() Authentication Bypass :\n\tUse of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed. Third-party module writers SHOULD use ap_get_basic_auth_components(), available in 2.2.34 and 2.4.26, instead of ap_get_basic_auth_pw(). Modules which call the legacy ap_get_basic_auth_pw() during the authentication phase MUST either immediately authenticate the user after the call, or else stop the request immediately with an error response, to avoid incorrectly authenticating the current request.\n ii) mod_ssl Null Pointer Dereference :\n\tmod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port.\n iii) ap_find_token() Buffer Overread :\n\tThe HTTP strict parsing changes added in 2.2.32 and 2.4.24 introduced a bug in token list parsing, which allows ap_find_token() to search past the end of its input string. By maliciously crafting a sequence of request headers, an attacker may be able to cause a segmentation fault, or to force ap_find_token() to return an incorrect value.\n iv) mod_mime Buffer Overread :\n\tmod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.\n v) Uninitialized memory reflection in mod_auth_digest :\n\tThe value placeholder in [Proxy-]Authorization headers of type \'Digest\' was not initialized or reset before or between successive key=value assignments. by mod_auth_digest. Providing an initial key with no \'=\' assignment could reflect the stale value of uninitialized pool memory used by the prior request, leading to leakage of potentially confidential information, and a segfault.\n vi) mod_userdir CRLF injection :\n\tPossible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value.\n vii) mod_status buffer overflow :\n\tA race condition was found in mod_status. An attacker able to access a public server status page on a server using a threaded MPM could send a carefully crafted request which could lead to a heap buffer overflow. Note that it is not a default or recommended configuration to have a public accessible server status page.\n vii) mod_cgid denial of service :\n\tA flaw was found in mod_cgid. If a server using mod_cgid hosted CGI scripts which did not consume standard input, a remote attacker could cause child processes to hang indefinitely, leading to denial of service.\n '
                    sol='Upgrade to Apache version 2.3.2 or newer.'
                    ref='CVE-2008-0455,CVE-2008-0456,CVE-2017-9798,CVE-2017-3167,CVE-2017-3169,CVE-2017-7668,CVE-2017-7679,CVE-2017-9788,CWE:538'
                    link='https://httpd.apache.org/security/vulnerabilities_22.html,https://beyondsecurity.com/scan-pentest-network-vulnerabilities-apache-mod-negotiation-multi-line-filename-upload-vulnerabilities.html#:~:text=Vulnerabilities%20in%20Apache%20mod_negotiation%20Multi-Line%20Filename%20Upload%20is,to%20resolve%20or%20prone%20to%20being%20overlooked%20entirely,https://bz.apache.org/bugzilla/show_bug.cgi?id=46837'

                    head=' [MED] APACHE MOD_NEGOTIATION IS ENABLED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-aspnet-debug' and re.search('DEBUG is enabled',script,re.IGNORECASE):
                    v_name='ASP.NET Debugging Enabled'
                    score=5.3
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='The ASP.NET application is running in debug mode which allows a remote user to glean information about an application by using the DEBUG verb in an HTTP request. This can leak information including source code, hidden filenames, and detailed error messages.'
                    imp='ASP.NET debugging is enabled on this application. It is recommended to disable debug mode before deploying a production application. By default, debugging is disabled, and although debugging is frequently enabled to troubleshoot a problem, it is also frequently not disabled again after the problem is resolved. An attacker might use this to alter the runtime of the remote scripts.'
                    sol='Make sure that DEBUG statements are disabled or only usable by authenticated users.'
                    ref='CWE:11'
                    link='https://support.microsoft.com/en-us,https://capec.mitre.org/data/definitions/37.html,https://www.tenable.com/plugins/nessus/33270,https://docs.microsoft.com/en-US/troubleshoot/developer/webapps/aspnet/development/disable-debugging-application'

                    head=' [MED] ASP.NET DEBUGGING ENABLED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-avaya-ipoffice-users':# and re.search(,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-awstatstotals-exec.' and re.search('Output for',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-brute':
                    pass
                    ##DUE

                if str(j)=='http-comments-displayer':
                    pass
                    ##DUE

                if str(j)=='http-config-backup':
                    pass
                    ##DUE

                if str(j)=='http-cookie-flags':
                    if re.search('secure flag not set',script,re.IGNORECASE):
                        v_name='Cookie Not Marked As Secure'
                        score=4.3
                        strng='CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N'
                        risk='Medium'
                        desc='The remote web application uses cookies to track authenticated users. However, there are instances where the application is running over unencrypted HTTP or the cookie(s) are not marked \'secure\', meaning the browser could send them back over an unencrypted link under certain circumstances.'
                        imp='This cookie will be transmitted over a HTTP connection, therefore an attacker might intercept it and hijack a victim\'s session. If the attacker can carry out a man-in-the-middle attack, he/she can force the victim to make an HTTP request to your website in order to steal the cookie.'
                        sol='Host the web application on a server that only provides SSL (HTTPS).Mark all cookies as \'secure\'.'
                        ref='CWE:522,CWE:718,CWE:724,CWE:928,CWE:930'
                        link='http://www.nessus.org/u?1c015bda,https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/session-cookie-not-marked-as-secure/'

                        head=' [MED] COOKIE NOT SECURE'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('httponly flag not set',script,re.IGNORECASE):
                        v_name='Cookie Without HttpOnly Flag Set'
                        score=0.0
                        strng=''
                        risk='Informational'
                        desc='One or more cookies don\'t have the HttpOnly flag set. When a cookie is set with the HttpOnly flag, it instructs the browser that the cookie can only be accessed by the server and not by client-side scripts. This is an important security protection for session cookies.'
                        imp='If the HttpOnly attribute is set on a cookie, then the cookie\'s value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie\'s value via an injected script.'
                        sol='There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie\'s value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing.'
                        ref='CWE:16,CWE:1004'
                        link=''

                        head=' [MED] COOKIE WITHOUT HTTP-ONLY'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-cors':
                    pass
                    ##DUE

                if str(j)=='http-cross-domain-policy' and re.search('State: VULNERABLE',script,re.IGNORECASE):
                    v_name='Cross-domain Policy File'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The remote web server contains a cross-domain policy file. This is a simple XML file used by Adobe’s Flash Player to allow access to data that resides outside the exact web domain from which a Flash movie file originated.'
                    imp='This is a simple XML file used by Adobe’s Flash Player to allow access to data that resides outside the exact web domain from which a Flash movie file originated.'
                    sol='Review the contents of the policy file carefully. Improper policies, especially an unrestricted one with just ‘*’, could allow for cross-site request forgery and cross-site scripting attacks against the web server.'
                    ref='CVE-2015-7369'
                    link='http://blog.jeremiahgrossman.com/2008/05/crossdomainxml-invites-cross-site.html,http://blogs.adobe.com/stateofsecurity/2007/07/crossdomain_policy_files_1.html'

                    head='[INFO] CROSS DOMAIN POLICY FILE FOUND'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-csrf' and re.search('vulnerabilities:',script,re.IGNORECASE):
                    v_name='Possible CSRF (Cross-site request forgery)'
                    score=4.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'
                    risk='Medium'
                    desc='This alert requires manual confirmation.Cross-Site Request Forgery (CSRF, or XSRF) is a vulnerability wherein an attacker tricks a victim into making a request the victim did not intend to make. Therefore, with CSRF, an attacker abuses the trust a web application has with a victim\'s browser.'
                    imp='CSRF will possibly work assuming the potential victim is authenticated. A CSRF attacker can bypass the authentication process to enter a web application when a victim with extra privileges performs activities that are not available to everybody, which is when CSRF attacks are used. Like web-based financial situations.There are two principal parts to executing a Cross-Site Request Forgery (CSRF) attack.\ni) The first part is to fool the victim into clicking a link or loading up a page. This is normally done through social engineering. An attacker will lure the client into tapping the link by utilizing social engineering strategies.\nii) Another part is to send a “forged” or made up request to the client’s browser. This connection will send an authentic-looking request to web application. The request will be sent with values that the attacker needs. Aside from them, this request will include any client’s cookies related to that site. As cookies are sent, the web application realizes that this client can play out specific activities on the web-site based upon the authorization level of the victim. The web applications will think about these requests as unique. However, the victim would send the request at the attacker’s command. A CSRF attack essentially exploits how the browser sends the cookies to the web application consequently with every single request.'
                    sol='Verify if this form requires anti-CSRF protection and implement CSRF countermeasures if necessary.The recommended and the most widely used technique for preventing CSRF attacks is know as an anti-CSRF token, also sometimes referred to as a synchronizer token. The characteristics of a well designed anti-CSRF system involve the following attributes.\ni) The anti-CSRF token should be unique for each user session.\nii) The session should automatically expire after a suitable amount of time.\niii) The anti-CSRF token should be a cryptographically random value of significant length.\niv) The anti-CSRF token should be cryptographically secure, that is, generated by a strong Pseudo-Random Number Generator (PRNG) algorithm.\nv) The anti-CSRF token is added as a hidden field for forms, or within URLs (only necessary if GET requests cause state changes, that is, GET requests are not idempotent).\nvi) The server should reject the requested action if the anti-CSRF token fails validation.\nWhen a user submits a form or makes some other authenticated request that requires a Cookie, the anti-CSRF token should be included in the request. Then, the web application will then verify the existence and correctness of this token before processing the request. If the token is missing or incorrect, the request can be rejected.'
                    ref='CWE:352,CVE-2006-5476'
                    link='https://www.acunetix.com/websitesecurity/csrf-attacks/,https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html,https://www.cgisecurity.com/csrf-faq.html'

                    head=' [MED] POSSIBLE CSRF INJECTION'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-default-accounts' and re.search('at /',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-dlink-backdoor' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='D-Link Router Authentication Bypass Backdoor Vulnerability'
                    score=0.0
                    strng=''
                    risk='High'
                    desc='A vulnerability was reported in D-Link Routers. A remote user can gain administrative access on the target device.'
                    imp='A remote user can send a specially crafted HTTP request with the HTTP User-Agent set to \'xmlset_roodkcableoj28840ybtide\' to bypass authentication and gain administrative access on the target device.The vulnerability is due to a non-secure backdoor(Elevation of Privilege).'
                    sol='Before installation of the software, please visit the software manufacturer web-site for more details.Update avaliable at http://www.dlink.com/uk/en/support/security (update on 3 Dec 2013)'
                    ref=''
                    link='http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/,http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/,http://securitytracker.com/id/1029174'

                    head='[HIGH] D_LINK BACKDOOR FOUND'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-dombased-xss' and re.search('Found the following',script,re.IGNORECASE):
                    v_name='DOM Based Cross-Site scripting'
                    score=6.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
                    risk='Medium'
                    desc='Client-side scripts are used extensively by modern web applications. They perform from simple functions (such as the formatting of text) up to full manipulation of client-side data and Operating System interaction.'
                    imp='Unlike traditional Cross-Site Scripting (XSS), where the client is able to inject scripts into a request and have the server return the script to the client, DOM XSS does not require that a request be sent to the server and may be abused entirely within the loaded page.his occurs when elements of the DOM (known as the sources) are able to be manipulated to contain untrusted data, which the client-side scripts (known as the sinks) use or execute an unsafe way.'
                    sol='Client-side document rewriting, redirection, or other sensitive action, using untrusted data, should be avoided wherever possible, as these may not be inspected by server side filtering.To remedy DOM XSS vulnerabilities where these sensitive document actions must be used, it is essential to:\ni) Ensure any untrusted data is treated as text, as opposed to being interpreted as code or mark-up within the page.\nii) Escape untrusted data prior to being used within the page. Escaping methods will vary depending on where the untrusted data is being used. (See references for details.)\niii) Use `document.createElement`, `element.setAttribute`, `element.appendChild`, etc. to build dynamic interfaces as opposed to HTML rendering methods such as `document.write`, `document.writeIn`, `element.innerHTML`, or `element.outerHTML `etc.'
                    ref='CWE:79'
                    link='http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting,https://www.owasp.org/index.php/DOM_Based_XSS,https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet'

                    head=' [MED] DOM BASED XSS'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-fileupload-exploiter' and re.search('Successfully uploaded',script,re.IGNORECASE):
                    v_name='Unrestricted File Upload Vulnerability'
                    score=9.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
                    risk='Critical'
                    desc='File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.'
                    imp='The impact of file upload vulnerabilities generally depends on two key factors:\n i) Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.\n ii) What restrictions are imposed on the file once it has been successfully uploaded.\nIn the worst case scenario, the file\'s type isn\'t validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.\nIf the filename isn\'t validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations.\nFailing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.'
                    sol='Restrict file types accepted for upload: check the file extension and only allow certain files to be uploaded. Use a whitelist approach instead of a blacklist. Check for double extensions such as .php.png. Check for files without a filename like .htaccess (on ASP.NET, check for configuration files like web.config). Change the permissions on the upload folder so the files within it are not executable. If possible, rename the files that are uploaded.'
                    ref='CWE:434,CVE-2018-15961,CWE:200'
                    link='https://www.owasp.org/index.php/Unrestricted_File_Upload,https://www.acunetix.com/websitesecurity/upload-forms-threat/'

                    head='[CRIT] FILE UPLOAD VULNERABILTY'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-frontpage-login' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-git' and re.search('Git repository found!',script,re.IGNORECASE):
                    v_name='Git Repository Found'
                    score=5.8
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N'
                    risk='Medium'
                    desc='Git metadata directory (.git) was found in this folder.'
                    imp='An attacker can extract sensitive information by requesting the hidden metadata directory that version control tool Git creates. The metadata directories are used for development purposes to keep track of development changes to a set of source code before it is committed back to a central repository (and vice-versa). When code is rolled to a live server from a repository, it is supposed to be done as an export rather than as a local working copy, and hence this problem.'
                    sol='Remove these files from production systems or restrict access to the .git directory. To deny access to all the .git folders you need to add the following lines in the appropriate context (either global config, or vhost/directory, or from .htaccess)'
                    ref='CWE:527'
                    link='http://www.ducea.com/2006/08/11/apache-tips-tricks-deny-access-to-some-folders/'

                    head=' [MED] GIT REPO FOUND'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-gitweb-projects-enum' and re.search('Projects from',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-google-malware':# and re.search():
                    pass
                    ##DUE

                if str(j)=='http-huawei-hg5xx-vuln' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='Remote Credential And Information Disclosure In Modems Huawei HG5XX'
                    score=0.0
                    strng=''
                    risk='Unknown'
                    desc='Modems Huawei 530x, 520x and possibly others are vulnerable to remote credential and information disclosure.'
                    imp='Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to extract sensitive information including PPPoE credentials, firmware version, model, gateway, dns servers and active connections among other values.'
                    sol=''
                    ref=''
                    link='http://routerpwn.com/#huawei,http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure'

                    head=' [???] HUAWEI INFORMATION DISCLOSURE'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-iis-short-name-brute' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='Microsoft IIS Tilde Character "~" Short Name Disclosure'
                    score=6.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L'
                    risk='Medium'
                    desc='Microsoft IIS Tilde Character Short File/Folder Name Disclosure'
                    imp='Microsoft Internet Information Server (IIS) suffers from a vulnerability which allows the detection of short names of files and directories which have en equivalent in the 8.3 version of the file naming scheme. By crafting specific requests containing the tilde \'~\' character, an attacker could leverage this vulnerability to find files or directories that are normally not visible and gain access to sensitive information. Given the underlying filesystem calls generated by the remote server, the attacker could also attempt a denial of service on the target application.'
                    sol='As a workaround, disable the 8.3 file and directories name creation, manually remove names already present in the fileystem and ensure that URL requests containing the tilde character (and its unicode equivalences) are discarded before reaching the IIS server.If possible, upgrade to the latest version of the .NET framework and IIS server.'
                    ref='CWE:20'
                    link='https://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/,https://soroush.secproject.com/blog/2014/08/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/,https://github.com/irsdl/IIS-ShortName-Scanner,https://support.microsoft.com/en-gb/help/121007/how-to-disable-8-3-file-name-creation-on-ntfs-partitions'

                    head=' [MED] MS IIS SHORTNAME DISCLOSURE'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-iis-webdav-vuln' and re.search('is ENABLED',script,re.IGNORECASE):
                    v_name='WebDAV Extension Is Enabled'
                    score=3.9
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N'
                    risk='Low'
                    desc='WebDAV is an extension to the HTTP protocol. It allows authorized users to remotely add and change content on your web server.'
                    imp='If WebDAV is not configured properly it may allow remote users to modify the content of the website.'
                    sol='If you are not using this extension, it\'s recommended to be disabled.'
                    ref='CWE:16'
                    link='http://www.securiteam.com/windowsntfocus/5FP0B2K9FY.html'

                    head=' [LOW] WEBDAV ENABLED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-internal-ip-disclosure' and re.search('Leaked',script,re.IGNORECASE):
                    v_name='Internal IP Disclosure'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='One or more strings matching an internal IPv4 address were found. These IPv4 addresses may disclose information about the IP addressing scheme of the internal network. This information can be used to conduct further attacks.The significance of this finding should be confirmed manually.'
                    imp='N/A'
                    sol='Prevent this information from being displayed to the user.'
                    ref='CWE:200'
                    link='https://www.invicti.com/blog/web-security/information-disclosure-issues-attacks/'

                    head='[INFO] INTERNAL IP DISCLOSURE'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-litespeed-sourcecode-download':
                    pass
                    ##DUE

                if str(j)=='http-ls':
                    pass
                    ##DUE

                if str(j)=='http-malware-host' and re.search('Host appears to be infected',script,re.IGNORECASE):
                    v_name='Malware Detected'
                    score=9.6
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
                    risk='Critical'
                    desc='Service appears to contain malware'
                    imp='Malware is malicious software that may attempt to install dangerous software on visitor\'s computers to steal or delete personal information. The URL from alert details was marked as malware on at least one malware database.'
                    sol='If your site has been infected with malware, you need to take it offline and identify the malware source. Once you\'ve identified the source of the problem, you should clean up your site and take action to prevent reinfection. Consult Web references for more information.'
                    ref='CWE:506'
                    link='https://transparencyreport.google.com/safe-browsing/search,https://www.yandex.com/safety/,https://cloud.google.com/web-risk/docs/advisory/,https://www.virustotal.com/gui/'

                    head='[CRTIC] POSSIBLE MALWARE FOUND'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-methods' :
                    if re.search('OPTIONS',script,re.IGNORECASE):
                        v_name='OPTIONS Method Enabled'
                        score=0.0
                        strng=''
                        risk='Informational'
                        desc='OPTIONS method is allowed. This issue is reported as extra information.'
                        imp='Information disclosed from this page can be used to gain additional information about the target system.'
                        sol='Disable OPTIONS method in all production systems.'
                        ref='CWE:16'
                        link='https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006),http://www.nessus.org/u?d9c03a9a,http://www.nessus.org/u?b019cbdb'

                        head='[INFO] OPTIONS METHOD ENABLED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('TRACE',script,re.IGNORECASE):
                        v_name='TRACE Method Enabled'
                        score=5.3
                        strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                        risk='Medium'
                        desc='HTTP TRACE method is enabled on this web server. In the presence of other cross-domain vulnerabilities in web browsers, sensitive header information could be read from any domains that support the HTTP TRACE method.'
                        imp='An attacker can use this information to conduct further attacks.'
                        sol='Disable TRACE method to avoid attackers using it to better exploit other vulnerabilities.'
                        ref='CVE-2003-1567,CVE-2004-2320,CVE-2010-0386,CWE:16,CWE:200,CERT:288308,CERT:867593'
                        link='https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf,http://www.apacheweek.com/issues/03-01-24,https://download.oracle.com/sunalerts/1000718.1.html'

                        head=' [MED] TRACE METHOD ENABLED'
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-method-tamper' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='HTTP Verb Tampering'
                    score=6.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
                    risk='Medium'
                    desc='By manipulating the HTTP verb it was possible to bypass the authorization on this directory. The scanner sent a request with a custom HTTP verb (WVS in this case) and managed to bypass the authorization. The attacker can also try any of the valid HTTP verbs, such as HEAD, TRACE, TRACK, PUT, DELETE, and many more.'
                    imp='An application is vulnerable to HTTP Verb tampering if the following conditions hold:\ni) it uses a security control that lists HTTP verbs\nii) the security control fails to block verbs that are not listed\niii) it has GET functionality that is not idempotent or will execute with an arbitrary HTTP verb.'
                    sol='In the case of Apache + .htaccess, don\'t use HTTP verb restrictions or use LimitExcept.Check references for more information on how to fix this problem on other platforms.'
                    ref='CWE:285,CVE-2020-4779'
                    link='https://www.owasp.org/index.php/Testing_for_HTTP_Verb_Tampering_(OTG-INPVAL-003),https://www.imperva.com/learn/application-security/http-verb-tampering/#:~:text=HTTP%20Verb%20Tampering%20is%20an%20attack%20that%20exploits,access%20to%20restricted%20resources%20by%20other%20HTTP%20methods.'

                    head=' [MED] HTTP VERB TAMPERING'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-open-proxy' and re.search('Potentially',script,re.IGNORECASE):
                    v_name='HTTP Open Proxy Detection'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The remote web proxy server accepts requests.'
                    imp='The remote web proxy accepts unauthenticated HTTP requests from the Nessus scanner. By routing requests through the affected proxy, a user may be able to gain some degree of anonymity while browsing websites, which will see requests as originating from the remote host itself rather than the user\'s host.'
                    sol='Make sure access to the proxy is limited to valid users/hosts.'
                    ref=''
                    link=''

                    head='[INFO] HTTP OPEN PROXY DETECTED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-open-redirect' and (re.search('https://',script,re.IGNORECASE) or re.search('http://',script,re.IGNORECASE)):
                    v_name='Open Redirect'
                    score=4.7
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N'
                    risk='Medium'
                    desc='The web application accepts a parameter value that allows redirects to unrestricted locations.'
                    imp='The remote web application contains functionality to redirect to a specific URL. This functionality is not restricted to relative URLs within the application and could be leveraged by an attacker to fool an end user into believing that a malicious URL they were redirected to is valid.'
                    sol='Parameters that are used to dynamically redirect must be restricted to paths within the application. If relative paths are accepted, the base path should be explicitly prepended.'
                    ref='CWE:601,CVE-2020-1323'
                    link='https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/'

                    head=' [MED] OPEN REDIRECTION ENABLED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-passwd' and re.search('Directory traversal found',script,re.IGNORECASE):
                    v_name='Directory Traversal'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.'
                    imp='Directory Traversal is a vulnerability which allows attackers to access restricted directories and read files outside of the web server\'s root directory.'
                    sol='The most effective way to prevent file path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.If it is considered unavoidable to pass user-supplied input to filesystem APIs, then two layers of defense should be used together to prevent attacks:\n i) The application should validate the user input before processing it. Ideally, the validation should compare against a whitelist of permitted values. If that isn\'t possible for the required functionality, then the validation should verify that the input contains only permitted content, such as purely alphanumeric characters.\n ii) After validating the supplied input, the application should append the input to the base directory and use a platform filesystem API to canonicalize the path. It should verify that the canonicalized path starts with the expected base directory.'
                    ref='CWE:22,CVE-2021-30497'
                    link='https://www.acunetix.com/websitesecurity/directory-traversal/'

                    head=' [MED] DIRECTORY TRAVERSAL'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-phpmyadmin-dir-traversal' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion'
                    score=4.2
                    strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P'
                    risk='Medium'
                    desc='The remote web server contains a PHP application that is prone to a local file inclusion flaw.'
                    imp='The version of phpMyAdmin installed on the remote host allows attackers to read and possibly execute code from arbitrary files on the local host because of its failure to sanitize the parameter \'subform\' before using it in the \'libraries/grab_globals.lib.php\' script.'
                    sol='Upgrade to phpMyAdmin 2.6.4-pl2 or later.'
                    ref='CVE-2005-3299'
                    link='http://securityreason.com/achievement_securityalert/24,http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-4'

                    head=' [MED] PHPMYADMIN LOCAL FILE INCLUSION'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-phpself-xss' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Unsafe use of $_SERVER["PHP_SELF"] in PHP files'
                    score=4.3
                    strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N'
                    risk='Medium'
                    desc='PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.'
                    imp=''
                    sol=''
                    ref='CVE-2011-3356,CWE:79'
                    link=''

                    head=' [MED] POSSIBLE PHP_SELF XSS'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-put' and re.search('successfully created',script,re.IGNORECASE):
                    v_name='HTTP PUT Method is Enabled'
                    score=7.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    risk='High'
                    desc='The remote web server allows the PUT method.'
                    imp='The PUT method allows an attacker to upload arbitrary web pages on the server. If the server is configured to support scripts like ASP, JSP, or PHP it will allow the attacker to execute code with the privileges of the web server.The DELETE method allows an attacker to delete arbitrary content from the web server.'
                    sol='Disable the PUT method in the web server configuration.'
                    ref='CVE-2021-35243'
                    link='https://tools.ietf.org/html/rfc7231#section-4.3.4,https://tools.ietf.org/html/rfc7231#section-4.3.5'

                    head=' [MED] HTTP PUT METHOD'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-rfi-spider' :#and re.search('',script):
                    pass
                    ##DUE

                if str(j)=='http-robots.txt' and re.search('disallowed entr',script,re.IGNORECASE):
                    v_name='robots.txt Information Disclosure'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The file robots.txt is used to give instructions to web robots, such as search engine crawlers, about locations within the web site that robots are allowed, or not allowed, to crawl and index.The presence of the robots.txt does not in itself present any kind of security vulnerability. However, it is often used to identify restricted or private areas of a site\'s contents. The information in the file may therefore help an attacker to map out the site\'s contents, especially if some of the locations identified are not linked from elsewhere in the site. If the application relies on robots.txt to protect access to these areas, and does not enforce proper access control over them, then this presents a serious vulnerability.'
                    imp='The remote host contains a file named \'robots.txt\' that is intended to prevent web \'robots\' from visiting certain directories in a website for maintenance or indexing purposes. A malicious user may also be able to use the contents of this file to learn of sensitive documents or directories on the affected site and either retrieve them directly or target them for other attacks.'
                    sol='Review the contents of the site\'s robots.txt file, use Robots META tags instead of entries in the robots.txt file, and/or adjust the web server\'s access controls to limit access to sensitive material.'
                    ref=''
                    link='http://www.robotstxt.org/orig.html'

                    head='[INFO] ROBOTS.TXT FOUND'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-sap-netweaver-leak' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Anonymous Access To SAP Netweaver Portal'
                    score=7.5
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                    risk='High'
                    desc='SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information including file system structure, LDAP users, emails and other information.'
                    imp='Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:\n i) SAP Netweaver AS - versions 700, 701, 702, 710, 711, 730, 740, 750, 751, 752, 753, 754, 755, 756 - contain a cross-site scripting vulnerability that allows an unauthenticated attacker to inject code that may expose sensitive data. (CVE-2022-22534).\n ii) SAP NetWeaver AS ABAP (Workplace Server) - versions 700, 701, 702, 731, 740 750, 751, 752, 753, 754, 755, 756, 787 - contain a SQL injection vulnerability that allows an attacker to execute crafted database queries that could expose the backend database. (CVE-2022-22540).\n iii) SAP NetWeaver AS ABAP - versions 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756 - contain an information disclosure vulnerability that aloows an authenticated attacker to read connection details stored with the destination for http calls. (CVE-2022-22545)'
                    sol=''
                    ref='CVE-2022-22545,CVE-2022-22540,CVE-2022-22534'
                    link='https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm'

                    head='[HIGH] ANONYMUS ACCESS TO SAP NETWEAVER PORTAL'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-shellshock' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='HTTP Shellshock Vulnerability'
                    score=9.8
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='This web application might be affected by the vulnerability known as Shellshock. It seems the server is executing commands injected via malicious HTTP headers.'
                    imp='At first, the vulnerability doesn\'t look all that serious. Executing commands is what bash is used for. But in this case, code can be executed without the user\'s intent by setting an environment variable.The most problematic scenario is bash scripts executed via cgi-bin. The CGI specification requires the web server to convert HTTP request headers supplied by the client to environment variables. If a bash script is called via cgi-bin, an attacker may use this to execute code as the web server.'
                    sol='Since the patch is incomplete, you should try to implement additional measures to protect your systems. Various Intrusion Detection System (IDS) and Web Application Firewall (WAF) vendors have released rules to block exploitation. Realize that these rules may be incomplete as well. Many rules I have seen so far just look for the string "() {" which was present in the original proof of concept exploit, but could easily be changed for example by adding more or different white spaces.You could switch your default shell to an alternative like ksh or sh. But this,will likely break existing scripts. Different shells use slightly different syntax.On many embedded systems you may already use an alternative shell ("busybox") that is not vulnerable. Another option to limit the impact of the vulnerability is SELinux, but by default, it does not prevent the initial exploit.'
                    ref='CVE-2014-6271'
                    link='http://www.openwall.com/lists/oss-security/2014/09/24/10,https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169,http://seclists.org/oss-sec/2014/q3/685,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271'

                    head='[CRIT] HTTP SHELLSHOCK VULNERABILTY'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if (str(j)=='http-slowloris-check' or str(j)=='http-slowloris') and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Slowloris DOS Attack'
                    score=7.5
                    risk='High'
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
                    desc='Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.  It accomplishes this by opening connections to the target web server and sending a partial request. By doing so, it starves    the http server\'s resources causing Denial Of Service.'
                    imp='Slowloris is an application layer attack which operates by utilizing partial HTTP requests. The attack functions by opening connections to a targeted Web server and then keeping those connections open as long as it can.\nSlowloris is not a category of attack but is instead a specific attack tool designed to allow a single machine to take down a server without using a lot of bandwidth. Unlike bandwidth-consuming reflection-based DDoS attacks such as NTP amplification, this type of attack uses a low amount of bandwidth, and instead aims to use up server resources with requests that seem slower than normal but otherwise mimic regular traffic. It falls in the category of attacks known as “low and slow” attacks. The targeted server will only have so many threads available to handle concurrent connections. Each server thread will attempt to stay alive while waiting for the slow request to complete, which never occurs. When the server’s maximum possible connections has been exceeded, each additional connection will not be answered and denial-of-service will occur.\nA Slowloris attack occurs in 4 steps: \n i) The attacker first opens multiple connections to the targeted server by sending multiple partial HTTP request headers.\n ii) The target opens a thread for each incoming request, with the intent of closing the thread once the connection is completed. In order to be efficient, if a connection takes too long, the server will timeout the exceedingly long connection, freeing the thread up for the next request.\n iii) To prevent the target from timing out the connections, the attacker periodically sends partial request headers to the target in order to keep the request alive. In essence saying, “I’m still here! I’m just slow, please wait for me.”\n iv) The targeted server is never able to release any of the open partial connections while waiting for the termination of the request. Once all available threads are in use, the server will be unable to respond to additional requests made from regular traffic, resulting in denial-of-service.\nThe key behind a Slowloris is its ability to cause a lot of trouble with very little bandwidth consumption.'
                    sol='For web servers that are vulnerable to Slowloris, there are ways to mitigate some of the impact. Mitigation options for vulnerable servers can be broken down into 3 general categories:\nIncrease server availability - Increasing the maximum number of clients the server will allow at any one time will increase the number of connections the attacker must make before they can overload the server. Realistically, an attacker may scale the number of attacks to overcome server capacity regardless of increases.\nRate limit incoming requests - Restricting access based on certain usage factors will help mitigate a Slowloris attack. Techniques such as limiting the maximum number of connections a single IP address is allowed to make, restricting slow transfer speeds, and limiting the maximum time a client is allowed to stay connected are all approaches for limiting the effectiveness of low and slow attacks.\nCloud-based protection - Use a service that can function as a reverse proxy, protecting the origin server.'
                    ref='CVE-2018-12122,CVE-2007-6750'
                    link='http://ha.ckers.org/slowloris/,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750'

                    head='[HIGH] SLOWLORIS DOS ATTACK'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-sql-injection' and re.search('Possible sqli',script,re.IGNORECASE):
                    v_name='SQL Injection'
                    score=10.0
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N'
                    risk='Critical'
                    desc='SQL injection (SQLi) refers to an injection attack wherein an attacker can execute malicious SQL statements that control a web application\'s database server.SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application\'s content or behavior.\nIn some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack'
                    imp='A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Many high-profile data breaches in recent years have been the result of SQL injection attacks, leading to reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization\'s systems, leading to a long-term compromise that can go unnoticed for an extended period.'
                    sol='Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.'
                    ref='CWE:89,CVE-2022-26201,CVE-2022-24646,CVE-2022-24707,CVE-2022-25506,CVE-2022-25404, CVE-2022-25394'
                    link='https://www.acunetix.com/websitesecurity/sql-injection/,https://www.acunetix.com/websitesecurity/sql-injection2/,https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/,https://www.owasp.org/index.php/SQL_Injection,http://pentestmonkey.net/category/cheat-sheet/sql-injection'

                    head='[HIGH] SQL INJECTION VULNERABILTY'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-trace' and re.search('is enabled',script,re.IGNORECASE):
                    v_name='TRACE Method Enabled'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='HTTP TRACE method is enabled on this web server. In the presence of other cross-domain vulnerabilities in web browsers, sensitive header information could be read from any domains that support the HTTP TRACE method.'
                    imp='An attacker can use this information to conduct further attacks.'
                    sol='Disable TRACE method to avoid attackers using it to better exploit other vulnerabilities.'
                    ref='CVE-2003-1567,CVE-2004-2320,CVE-2010-0386,CWE:16,CWE:200,CERT:288308,CERT:867593'
                    link='https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf,http://www.apacheweek.com/issues/03-01-24,https://download.oracle.com/sunalerts/1000718.1.html'

                    head=' [MED] TRACE METHOD ENABLED'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-traceroute' and len(script)>10:
                    v_name='Traceroute Information'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='It was possible to obtain traceroute information.'
                    imp='Makes a traceroute to the remote host.'
                    sol='N/A'
                    ref=''
                    link=''

                    head='[INFO] TRACEROUTE INFORMATION'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-userdir-enum' and re.search('Potential Users',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-vmware-path-vuln' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='VMWARE Path Traversal'
                    score=5.0
                    strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
                    risk='Medium'
                    desc='Directory traversal vulnerability in VMware Server 1.x before 1.0.10 build 203137 and 2.x before 2.0.2 build 203138 on Linux, VMware ESXi 3.5, and VMware ESX 3.0.3 and 3.5 allows remote attackers to read arbitrary files via unspecified vectors.'
                    imp='VMware is a set of server-emulation applications available for several platforms.Multiple VMware products are prone to a directory-traversal vulnerability because they fail to sufficiently sanitize user-supplied input. Attackers on the same subnetwork may use a specially crafted request to retrieve arbitrary files from the host operating system.A remote attacker could exploit the vulnerability using directory-traversal characters to access arbitrary files that contain sensitive information that could aid in further attacks.\nAffected :\n\t1.VMWare Server 2.0.1 build 156745\n\t2.VMWare Server 2.0.1\n\t3.VMWare Server 1.0.9 build 156507\n\t4.VMWare Server 1.0.9\n\t5.VMWare Server 1.0.8 build 126538\n\t6.VMWare Server 1.0.8\n\t7.VMWare Server 1.0.7 build 108231\n\t7.VMWare Server 1.0.7\n\t8.VMWare Server 1.0.6 build 91891\n\t9.VMWare Server 1.0.6\n\t10.VMWare Server 1.0.5 Build 80187\n\t11.VMWare Server 1.0.5\n\t12.VMWare Server 1.0.4\n\t13.VMWare Server 1.0.3\n\t14.VMWare Server 1.0.2\n\t15.VMWare Server 2.0\n\t16.VMWare ESXi Server 3.5 ESXe350-20090440\n\t17.VMWare ESXi Server 3.5\n\t18.VMWare ESX Server 3.0.3\n\t19.VMWare ESX Server 3.0.3\n\t20.VMWare ESX Server 3.5 ESX350-200906407\n\t21.VMWare ESX Server 3.5 ESX350-200904401\n\t22.VMWare ESX Server 3.5'
                    sol='Use Non-Vulnerable Packages:\n\t1.VMWare Workstation 6.0.3\n\t2.VMWare Workstation 5.5.6\n\t3.VMWare Player 2.0.3\n\t4.VMWare Player 1.0.5\n\t5.VMWare ACE 2.0.3\n\t6.VMWare ACE 1.0.5\n\t7.VMWare ESX\n\t8.VMWare Server'
                    ref='CVE-2009-3733'
                    link='http://www.securityfocus.com/bid/36842,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3733'

                    head=' [MED] VMWARE PATH TRAVERSAL'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-vuln-misfortune-cookie' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Allegro RomPager 4.07 < 4.34 Multiple Vulnerabilities (Misfortune Cookie)'
                    score=9.8
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='The cookie handling routines in RomPager 4.07 are vulnerable to remote code execution. This script has verified the vulnerability by exploiting the web server in a safe manner.'
                    imp='Versions of RomPager 4.07 and prior to 4.34 are potentially affected by multiple issues :\n\t- A buffer overflow vulnerability exists because the RomPager web server fails to perform adequate bounds checks on user-supplied input. Attackers can exploit this issue to execute arbitrary code with the privileged access of RomPager.(CVE-2014-9223)\n\t- A security bypass vulnerability exists due to an error within the HTTP cookie management mechanism (aka, the \'Misfortune Cookie\' issue) which could allow any user to determine the \'fortune\' of a request by manipulating cookies. An attacker can exploit this issue to corrupt memory and alter the application state by sending specially crafted HTTP cookies. This could be exploited to gain the administrative privileges for the current session by tricking the attacked device. (CVE-2014-9222)'
                    sol='Contact the vendor for an updated firmware image. Allegro addressed both issues in mid-2005 with RomPager version 4.34.'
                    ref='CVE-2014-9222,CVE-2014-9223,CWE:119,CWE:17'
                    link='http://mis.fortunecook.ie/,http://www.nessus.org/u?e6bf690f,http://www.nessus.org/u?22cba06d,http://www.kb.cert.org/vuls/id/561444'

                    head='[CRTIC] ROMPAGER - MISFORTUNE COOKIE'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-vuln-wnr1000-creds' and re.search('VULNERABLE',script,re.IGNORECASE):
                    #v_name='Netgear WNR1000v3 Credential Harvesting'
                    pass
                    ##DUE

                if str(j)=='http-webdav-scan':
                    pass
                    ##DUE

                if str(j)=='http-xssed' and re.search('found the following previously reported XSS',script,re.IGNORECASE):
                    v_name='Cross-Site Scripting(XSS)'
                    score=6.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                    risk='Medium'
                    desc='Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user\'s data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application\'s functionality and data.'
                    imp='Cross-site Scripting (XSS) refers to client-side code injection attack wherein an attacker can execute malicious scripts into a legitimate website or web application. XSS occurs when a web application makes use of unvalidated or unencoded user input within the output it generates.\nThere are three main types of XSS attacks. These are:\n\tReflected XSS, where the malicious script comes from the current HTTP request.\n\tStored XSS, where the malicious script comes from the website\'s database.\n\tDOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.\nThe actual impact of an XSS attack generally depends on the nature of the application, its functionality and data, and the status of the compromised user. For example:\nIn a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.\nIn an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.\nIf the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.'
                    sol='Preventing cross-site scripting is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:\nFilter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.\nEncode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.\nUse appropriate response headers. To prevent XSS in HTTP responses that aren\'t intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.\nContent Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.'
                    ref='CWE:79,CVE-2020-10385'
                    link='http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting,https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet'

                    head=' [MED] CROSS-SITE SCRIPTING'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ip-https-discover':
                    pass
                    ##DUE

def _http_nm():
    res=_scan(host,'-sV --script=http-apache-negotiation.nse,http-avaya-ipoffice-users.nse,http-awstatstotals-exec.nse,http-brute.nse,http-comments-displayer.nse,http-config-backup.nse,http-cookie-flags,http-cors,http-cross-domain-policy.nse,http-csrf.nse,http-dombased-xss.nse,http-fileupload-exploiter.nse,http-frontpage-login.nse,http-git.nse,http-gitweb-projects-enum.nse,http-google-malware.nse,http-huawei-hg5xx-vuln.nse,http-iis-short-name-brute.nse,http-iis-webdav-vuln.nse,http-internal-ip-disclosure.nse,http-litespeed-sourcecode-download.nse,http-ls.nse,http-malware-host.nse,http-methods.nse,http-method-tamper.nse,http-open-proxy.nse,http-open-redirect.nse,http-passwd.nse,http-phpmyadmin-dir-traversal.nse,http-phpself-xss.nse,http-put,http-rfi-spider.nse,http-robots.txt.nse,http-shellshock.nse,http-slowloris-check.nse,http-sql-injection.nse,http-trace.nse,http-traceroute.nse,http-userdir-enum.nse,http-vmware-path-vuln.nse,http-vuln-misfortune-cookie.nse,http-vuln-wnr1000-creds.nse,http-webdav-scan.nse,http-xssed.nse,ip-https-discover.nse --script-args="basepath=/cf/adminapi/, basepath=/cf/, http-aspnet-debug.path=/path,http-awstatstotals-exec.cmd=uname, http-awstatstotals-exec.uri=/awstats/index.php, http-cross-domain-policy.domain-lookup=true, http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\',http-put.url=\'/uploads/rootme.php\', http-put.file=\'/tmp/rootme.php\', uri=/cgi-bin/bin, cmd=ls" -F')


    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

_http_nm()



res = sorted(result.items(), key = lambda x: x[1]['score'],reverse=True)

result={}
for i in res:
  x=i[0]
  y=dict(i[1])
  result[x]=y

print(json.dumps(result))
