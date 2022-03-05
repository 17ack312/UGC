import sys,os

import style,nmap



nm=nmap.PortScanner()

def _scan(ip,arg):
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    for i in res.keys():
        res=res[i]
    return res



def tcp_services(ip):
    res=_scan(ip,'-sV -O -Pn')
    print('[✓] UP TIME')
    print('[i] Last Boot : ' + str(res['uptime']['lastboot']))
    print('[i] Up Time   : ' + str(int(int(res['uptime']['seconds']) / (24 * 3600))) + ' Days')
    print('[✓] OPEN TCP PORTS AND SERVICES ')
    if 'tcp' not in res.keys():
        exit()
    else:
        res = res['tcp']
        print(('PORT,SERVICE,INFORMATION'))
        for i in res.keys():
            try:
                port = str(i)
            except:
                port = ''
            try:
                state = str(res[i]['state'])
            except:
                state = ''
            try:
                name = str(res[i]['name'])
            except:
                name = ''
            try:
                product = str(res[i]['product'])
            except:
                product = ''
            try:
                version = str(res[i]['version'])
            except:
                version = ''
            if state.lower() == 'open':
                print((port + ',' + name + ',' + product + ' ' + version))



def udp_services(ip):
    res=_scan(ip,'-sU')
    if 'udp' not in res.keys():
        exit()
    else:
        res = res['udp']
        print('PORT,SERVICE,INFORMATION')
        for i in res.keys():
            try:
                port = str(i)
            except:
                port = ''
            try:
                state = str(res[i]['state'])
            except:
                state = ''
            try:
                name = str(res[i]['name'])
            except:
                name = ''
            try:
                product = str(res[i]['product'])
            except:
                product = ''
            try:
                version = str(res[i]['version'])
            except:
                version = ''
            if state.lower() == 'open':
                print((port + ',' + name + ',' + product + ' ' + version))

ip=sys.argv[1]
flag=int(sys.argv[2])

if flag==1:
    tcp_services(ip)
if flag==2:
    udp_services(ip)
