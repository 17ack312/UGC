import sys
import nmap

nm=nmap.PortScanner()

def _scan(ip,arg):
    res=nm.scan(hosts=ip,arguments=arg)['scan']
    return res

def prepare_data(data,flag):
    master={}
    for i in data.keys():
        x=[]
        if flag in (data[i].keys()):
            y={}
            try:
                up=round(float(data[i]['uptime']['seconds'])/(24*3600))
            except:
                up=0
            try:
                last=str(data[i]['uptime']['lastboot'])
            except:
                last=''
            y['up']=str(up)+' days'
            y['last']=str(last)
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

                if 'open' in state:
                    x.append(str(port+','+name))
                y['port']=x
        master[i]=y
    print(master)

def tcp(hosts):
    res=_scan(hosts,'-sV -O')
    prepare_data(res,'tcp')

def udp(hosts):
    res=_scan(hosts,'-sU')
    prepare_data(res,'udp')



flag=sys.argv[1]
hosts=sys.argv[2]

if flag==1:
    tcp(hosts)
if flag==2:
    udp(hosts)

