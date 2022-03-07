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
    _rmdir(mod+'d_tect/')
except:
    pass

if not os.path.exists(mod+'d_tect/'):
    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/Devploit.git "'+mod+'d_tect/" --quiet')

try:
    res=os.popen('python2 "'+mod+'Devploit/Devploit" '+str(flag)+' "'+ip+'"').read()
except:
    res=None

print(res)