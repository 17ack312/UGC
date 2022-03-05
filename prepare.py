import os,sys,subprocess,re,tempfile,json,ctypes
import nmap,style

path=tempfile.gettempdir().replace('\\','/')+'/nexp/'
path='C:/Users/Rajdeep Basu/Desktop/UGC/module/'
out=path.replace('module','out')
try:
    os.mkdir(path)
except:
    pass
try:
    os.mkdir(out)
except:
    pass
nm=nmap.PortScanner()
def _run(comm):
    try:
        res = (os.popen('python ' + comm).read())
    except:
        res = (os.popen('python3 ' + comm).read())
    return res

def _scan(ip,arg):
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    for i in res.keys():
        res=res[i]
    return res

def lookup(ip,mac):
    comm = '"' + path + 'lookup.py" "' + ip + '" 1'
    print(style.bold(style.blue('[✓] WHOIS-LOOK UP ')))
    #print(style.bold(style.blue('[================]')))
    try:
        res = (_run(comm))
        if res != None:
            print(style.green(res))
    except:
        pass
    comm = '"' + path + 'lookup.py" "' + ip + '" 2'
    print(style.bold(style.blue('[✓] IP-LOOK UP ')))
    #print(style.bold(style.blue('[=============]')))
    try:
        res = (_run(comm))
        if res != None:
            print(style.green(res))
    except:
        pass
    if mac != None:
        print(style.bold(style.blue('[✓] MAC-LOOK UP ')))
        #print(style.bold(style.blue('[==============]')))
        comm = '"' + path + 'lookup.py" "' + mac + '" 3'
        try:
            res = (_run(comm))
            if res != None:
                print(style.green(res))
        except:
            pass

def get_service(ip):
    def _tcp():
        comm='"'+path+'_serv.py" '+ip+' 1'
        res=_run(comm)
        print(res)
    def _udp():
        comm='"'+path+'_serv.py" '+ip+' 2'
        res=_run(comm)
        print(res)

    _tcp()
    #_udp()



def _prepare():
    try:
        host = sys.argv[1]
    except:
        host = input('[>] Enter Host : ')
    if (re.search('[a-zA-Z]', host)):
        host = (host.strip().removeprefix('https://').removeprefix('http://').split('/')[0])
        ip = host
    else:
        ip = host
    res=_scan(ip,'-sn')

    if 'status' not in res.keys() or str(res['status']['state']).lower()!='up':
        sys.exit('Host is Down or Unreachable')
    else:
        ip=res['addresses']['ipv4']
        try:
            mac=res['addresses']['mac']
        except:
            mac=None
        try:
            hostname=[]
            for i in res['hostnames']:
                hostname.append(i['name'])
            hostname=list(set(hostname))
            hostname=str(",".join(hostname))
        except:
            hostname=None
        print(ip,mac,hostname)

        #lookup(ip,mac)
        get_service(ip)




if 'win' in str(sys.platform).lower():
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    if is_admin():
        _prepare()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        _prepare()
elif 'linux' in str(sys.platform).lower():
    if not os.geteuid() == 0:
        sys.exit('This script must be run as root!')
    else:
        _prepare()


