import os,sys,socket,subprocess,uuid,requests,re


def details():
    data = []
    def os_details():
        import platform
        import os
        print("OS NAME  :", os.name.upper())
        print("PLATFORM :", platform.system().upper())
        print("VERSION  :", platform.release().upper())
    def public_ip():

        res_data = requests.get('https://ipinfo.io/json').json()
        data.append(res_data['ip'])
    def local_service():
        l_name = socket.gethostname()
        data.append(l_name)
        l_IP = socket.gethostbyname(l_name)
        data.append(l_IP)
        # print(l_name,l_IP)
    def mac_add():
        data.append(':'.join(re.findall('..', '%012x' % uuid.getnode())))
    os_details()
    local_service()
    public_ip()
    mac_add()
    print(data)

details()