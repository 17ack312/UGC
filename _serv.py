import sys
import nmap

nm=nmap.PortScanner()

def _scan(ip,arg):
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    return res

def prepare_data(data,flag):
    master={}
    for i in data.keys():
        x=[];y={}
        if flag in (data[i].keys()):
            try:
                up=round(float(data[i]['uptime']['seconds'])/(24*3600))
            except:
                up=0
            try:
                last=str(data[i]['uptime']['lastboot'])
            except:
                last=''

            try:
                for j in (data[i]['osmatch']):
                    if float(j['accuracy']) > 85:
                        os = (j['name'])
                        for k in j['osclass']:
                            os = os + ',' + (k['type'])
            except:
                os=''

            y['up']=str(up)+' days'
            y['last']=str(last)
            y['os']=str(os)
            temp=data[i][flag]
            for j in temp.keys():
                port=str(j)
                state=str(temp[j]['state'])
                try:
                    name=str(temp[j]['name'])
                except:
                    name=''
                try:
                    prod=str(temp[j]['product'])
                except:
                    prod=''
                try:
                    ver=str(temp[j]['version'])
                except:
                    ver=''
                name=name+' '+prod+' '+ver

                if ('open' in state) or ('filtered' in state):
                    x.append(str(port+','+name))
                y['port']=x
        print(y)
        #master[i]=y
    #print(master)

def tcp(hosts):
    res=_scan(hosts,'-sV -O -F')
    prepare_data(res,'tcp')

def udp(hosts):
    res=_scan(hosts,'-sU -F')
    prepare_data(res,'udp')



flag=int(sys.argv[1])
hosts=sys.argv[2]

if flag==1:
    tcp(hosts)
if flag==2:
    udp(hosts)
