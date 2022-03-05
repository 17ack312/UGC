import subprocess
import sys,os,subprocess,requests,shutil

path=sys.argv[3]
mod = path + 'module/'
out = mod.replace('module', 'out')

ip=sys.argv[1]
python=sys.argv[2]

def _rmdir(path):
    if (os.path.exists(path)):
        shutil.rmtree(path)

try:
    _rmdir(mod+'Automater')
    os.system('git clone https://github.com/17ack312/Automater.git')
except:
    if not os.path.exists(mod+'Automater'):
        os.system('git clone https://github.com/17ack312/Automater.git')

res=os.popen(python+' "'+mod+'Automater/Automater.py" '+ip).read()

if 'Unfortunately there is neither a tekdefense.xml' not in res:
    print(res)
else:
    print(None)
