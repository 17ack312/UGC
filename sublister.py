import requests,sys,os,subprocess,tempfile





def _rmdir(path):

    if (os.path.exists(path)):

        shutil.rmtree(path)



path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'

mod = path + 'module/'

out = mod.replace('module', 'out')





ip=sys.argv[1]



try:

    _rmdir(mod+'sublister/')

except:

    pass



if not os.path.exists(mod+'sublister/'):

    os.system('cd "'+mod+'" && git clone https://github.com/17ack312/sublister.git "'+mod+'sublister/" --quiet')



try:

    res=os.popen('python3 "'+mod+'sublister/sublist3r.py" -d "'+ip+'"').read()

except:

    res=None



print(res)

