import os,sys,style,tempfile
temp_dir = tempfile.gettempdir().replace('\\','/')
path=temp_dir+'/mod/'
try:
    os.mkdir(path)
except:
    pass

path='"C:\\Users\\Rajdeep Basu\\Desktop\\UGC\\module\\"'

border="[======================================================================]"
welcome="""   ___     __  ________  ____      ____     ____   ____    __  _______
    | |    ||   | |   |   | |     | | \|   | |  |  | |\  /||   | |   |
    | | /\ ||   | |=|     | |     | |   /  | |  |  | | \/ ||   | |=|
    |_|/  \||  _|_|___|  _|_|___| |_|__/   |_|__|  |_|    ||  _|_|___|"""

print(style.bold(style.magenta(border)))
print(style.bold(style.magenta(welcome)))
print(style.bold(style.magenta(border)))

print(style.on_white(style.black(border)))
print(style.on_white(style.black("\t\t\t\t\t C H O O S E   F R O M   B E L O W \t\t\t\t\t")))
print(style.on_white(style.black(border)))
print(style.bold(style.blue("[1] LOOK UP ")))
print(style.bold(style.blue()))
print(style.bold(style.blue()))
print(style.bold(style.blue()))
print(style.bold(style.blue()))

choice=int(input(style.bold("[>] YOUR CHOICE : ")))

if choice==1:
    res=os.popen('python lookup.py')
    print(res)


