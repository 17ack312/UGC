import subprocess
import sys,os,subprocess,requests,shutil

path=sys.argv[2]
mod = path + 'module/'
out = mod.replace('module', 'out')

ip=sys.argv[1]

def _rmdir(path):
    if (os.path.exists(path)):
        shutil.rmtree(path)

try:
    _rmdir(mod+'Automater')
    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/Automater.git --quiet')
except:
    if not os.path.exists(mod+'Automater'):
    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/Automater.git --quiet')

res=os.popen('python2 "'+mod+'Automater/Automater.py" '+ip).read()

if 'Unfortunately there is neither a tekdefense.xml' not in res:
    print(res)
else:
    print(None)
