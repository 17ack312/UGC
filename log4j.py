import json,re,sys,os
import requests

url = "https://log4j-vulnerability-tester.p.rapidapi.com/v1/test"

#host='vckolkata63.org'

host=sys.argv[1]

if not(host.startswith('http')):
    host='http://'+host

#print(host)
querystring = {"url":host}

headers = {
    'x-rapidapi-host': "log4j-vulnerability-tester.p.rapidapi.com",
    'x-rapidapi-key': "6be506998emshd0400186b034514p11bc21jsnbcd08c437c02"
    }

response = requests.request("GET", url, headers=headers, params=querystring)

res=json.loads(response.text)

print(res)
