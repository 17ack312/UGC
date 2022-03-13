import requests,sys,os,subprocess,tempfile

def _rmdir(path):
    if (os.path.exists(path)):
        shutil.rmtree(path)

path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'
mod = path + 'module/'
out = mod.replace('module', 'out')

flag=int(sys.argv[1])
ip=sys.argv[2]

try:
    _rmdir(mod+'')
except:
    pass

if not os.path.exists(mod+'ssh-audit/'):
    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/ssh-audit.git "'+mod+'ssh-audit/" --quiet')

try:
    res=os.popen('python3 "'+mod+'ssh-audit/rhawk.php" '+ip).read()
except:
    res=None

print(res)
