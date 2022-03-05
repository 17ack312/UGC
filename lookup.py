import os,sys,subprocess
import nmap
from ipwhois import IPWhois
import requests, re, nmap, json, urllib.request, whois

def whois_lookup(ip):
    def def_whois():
        obj = IPWhois(ip)
        res = (obj.lookup_whois())
        try:
            for i in res['nets']:
                name = str(i['name'])
                handle = str(i['handle'])
                ran = str(i['range'])
                desc = str(i['description'])
                loc = str(i['address']) + ", " + str(i['city']) + "-" + str(i['postal_code']) + ", " + str(
                    i['state']) + ", " + str(i['country'])
                mail = ", ".join(i['emails'])
                create = str(i['created'])
                update = str(i['updated'])

                print("Name        :", name)
                print("Handle      :", handle)
                print("Range       :", ran)
                print("Description :", desc)
                print("Location    :", loc.replace('\n', ' '))
                print("E-mail      :", mail)
                print("Created on  :", create)
                print("Updated on  :", update)
        except:
            pass
    def_whois()

def mac_lookup(mac):
    url = "https://mac-address-lookup1.p.rapidapi.com/static_rapid/mac_lookup/"
    querystring = {"query": mac}
    headers = {'x-rapidapi-host': "mac-address-lookup1.p.rapidapi.com",
        'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"}
    response = requests.request("GET", url, headers=headers, params=querystring)
    response = json.loads(response.text)
    response = json.loads(str(response['result']).replace('\'', '"').replace('[', '').replace(']', ''))

    print("MAC Address  :", mac)
    print("Manufacturer :", response['name'])
    print("Address      :", response['address'])


def ip_lookup(host):
    def get_wether(loc):
        url = "https://yahoo-weather5.p.rapidapi.com/weather"
        querystring = {"location": loc, "format": "json", "u": "f"}
        headers = {'x-rapidapi-host': "yahoo-weather5.p.rapidapi.com",
            'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"}
        response = requests.request("GET", url, headers=headers, params=querystring)
        res = json.loads(str(response.text).replace('\'', '"'))
        print("\tLocation      :",str(res['location'].get('city')) + ',' + str(res['location'].get('region')) + ',' + str(res['location'].get('country')))
        print("\tTemparature   :", (float(res['current_observation'].get('condition').get('temperature')) - 32) // 1.8,'°C', '\t', "Condition    :", (str(res['current_observation'].get('condition').get('text'))))
        print("\tHumidity      :", str(res['current_observation'].get('atmosphere').get('humidity')), '\t\t', "Visibility   :", str(res['current_observation'].get('atmosphere').get('visibility')))

        week = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
        weekday = ["   Sunday", "   Monday", "  Tuesday", "Wednesday", " Thursday", "   Friday", " Saturday"]

        """
        print("\n\tForecast :")
        print("\t________________________________________________________________________")
        print("\t|                                                                      |")
        print("\t|      Date [Day]         | Highest (°C) | Lowest  (°C) | Condition    |")
        print("\t|______________________________________________________________________|")

        c = 1
        for i in res['forecasts']:
            d = (str(datetime.datetime.now() + datetime.timedelta(days=c)))
            d = (re.split("\s", d))
            d = d[0]
            day = i['day']
            day = (week.index(day))
            print('\t>> ' + d + ' [' + (weekday[day]) + '] |     ' + str((float(i['high']) - 32) // 1.8), '    |    ',str((float(i['low']) - 32) // 1.8), '    |', i['text'])
            c += 1
        print("\t________________________________________________________________________")
        """
    def get_postoffice(pin):
        url = "https://zipcodebase-zip-code-search.p.rapidapi.com/search"
        querystring = {"codes": pin}
        headers = {'x-rapidapi-host': "zipcodebase-zip-code-search.p.rapidapi.com",
            'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"}
        response = requests.request("GET", url, headers=headers, params=querystring)
        res = json.loads(response.text)
        res = (res["results"].get(pin))

        c = 1
        print("\tAvailable Post Offices:")
        for i in res:
            # print(i)
            print('\t[' + str(c) + '] ' + str(
                i['city'] + '(' + i['postal_code'] + '), ' + i['province'] + ', ' + i['state']).upper())
            c += 1

    res1 = requests.get('http://ip-api.com/json/' + host + '?fields=66846719')
    res1 = json.loads(res1.content)
    url = "https://find-any-ip-address-or-domain-location-world-wide.p.rapidapi.com/iplocation"
    querystring = {"ip": host, "apikey": "873dbe322aea47f89dcf729dcc8f60e8"}
    headers = {'x-rapidapi-host': "find-any-ip-address-or-domain-location-world-wide.p.rapidapi.com",
               'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"}
    response = requests.request("GET", url, headers=headers, params=querystring)
    res = json.loads(response.text)

    try:
        ip = str(res['ip'])
        print("IP Address      :", ip)
    except:
        pass
    try:
        net = str(res['network'])
        print("Network         :", net)
    except:
        pass
    try:
        org = str(res1['org']) + ", " + str(res1['as']) + " [" + str(res1['asname']) + "]"
        print("Organization    :", org)
    except:
        pass
    try:
        rev = str(res1['reverse'])
        print("Reverse Address :", )
    except:
        pass
    try:
        isp = str(res1['isp'])
        print("ISP             :", isp)
    except:
        pass
    try:
        loc = str(res1['lat']) + ", " + str(res1['lon'])
        print("Geo Location    :", loc)
    except:
        pass
    try:
        continent = str(res1['continent']) + " [" + str(res1["continentCode"]) + "]"
        print("Continent       :", continent)
    except:
        pass
    try:
        country = str(res['country']) + " [" + str(res['countryISO3']) + "(" + str(res['countryISO2']) + ")] - " + str(res['countryNativeName']) + "]"
        print("Country         :", country)
    except:
        pass
    try:
        capital = str(res['countryCapital'])
        print("Capital         :", capital)
    except:
        pass
    try:
        state = str(res1['regionName']) + " [" + str(res1["region"]) + "]"
        print("Region          :", state)
    except:
        pass
    try:
        city = str(res1['city'])
        print("City            :", city)
        try:
            get_wether(city)
        except:
            pass
    except:
        pass
    try:
        zip = str(res1['zip'])
        print("ZipCode         :", zip)
        try:
            get_postoffice(zip)
        except:
            pass
    except:
        pass
    try:
        tzone = str(res['gmt']) + ", " + str(res1['timezone'])
        print("Time-Zone       :", tzone)
    except:
        pass
    try:
        std = str(res['phoneCode'])
        print("STD Code        :", std)
    except:
        pass
    try:
        curr = str(res['currencyNamePlural']) + " (" + str(res['currencyCode']) + "), " + str(res['currencySymbol']) + "/" + str(res['currencySymbolNative'])
        print("Currency        :", curr)
    except:
        pass
    urllib.request.urlretrieve(res['flag'],'temp.png')
    # img = Image.open("temp.png")
    # img.show()

IN=sys.argv[1]
flag=int(sys.argv[2])

if flag==1:
    try:
        whois_lookup(IN)
    except:
        print(None)
if flag==2:
    try:
        ip_lookup(IN)
    except:
        print(None)
if flag==3:
    try:
        mac_lookup(IN)
    except:
        print(None)
