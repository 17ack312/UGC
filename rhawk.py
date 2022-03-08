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
    _rmdir(mod+'rhawk/')
except:
    pass

if not os.path.exists(mod+'rhawk/'):
    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/rhawk.git "'+mod+'rhawk/" --quiet')

try:
    res=os.popen('php -f "'+mod+'rhawk/rhawk.php" '+str(flag)+' "'+ip+'"').read()
except:
    res=None

print(res)
