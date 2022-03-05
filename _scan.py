import nmap,sys

nm=nmap.PortScanner()

host=sys.argv[1]
arg=sys.argv[2]

res = nm.scan(hosts=host, arguments=arg)
for i in res['scan'].keys():
    res = res['scan'][i]

print(res)