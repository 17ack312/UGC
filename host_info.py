import sys,json
import nmap
nm = nmap.PortScanner()

def _scan(ip):
	x={}
	res = nm.scan(hosts=ip, arguments='-sn')['scan']
	for i in res.keys():
		res=res[i]

		try:
			state=str(res['status']['state']).lower()
		except:
			state='down'
		names=[]
		if state=='up':
			ip=str(res['addresses']['ipv4'])
			try:
				mac=str(res['addresses']['mac'])
			except:
				mac=''
			for j in res['hostnames']:
				names.append(str(j['name']))
			x['ip']=ip
			x['mac']=mac
			x['name']=names
	return x

host=sys.argv[1]
data={}
for i in host.split('##'):
	x=(_scan(i))
	if int(len(x.keys()))>0:
		data[i]=x

print(json.dumps(data))
