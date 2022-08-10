from ast import parse
import json
import requests
import ipaddress
from collections import namedtuple

# Base query URL, IP will need to be appended before query is sent
queryUrl = "https://api.greynoise.io/v2/noise/context/"
ip = ""

# NOTE: 96.18.5.174 is a known malicious IP address, it will return a full data set from this query.
# 8.8.8.8 is a known NOT malicious IP address, and will only return IP address provided and "seen" boolean

# Request headers, ensuring data recieved is JSON and storing the key to the API
# Note, please don't use API key for evil :)
headers = {
    "Accept": "application/json",
    "key": "C2YTV9Z1T9blcxt47bNLhKaE1Pd7QpGQuXWxd4uxntr4EcN5cO5id6wq3ivxcLCv"
}

# Request IP to be queried from user as many times as necessary to get valid IP address
while ip == "":
    try:
        # This checks to make sure the input IP is valid. If it is not, it will throw a ValueError
        ip = ipaddress.ip_address(input("Please input the IP address of the device you would like to query:"))
    except ValueError:
        # If IP provided was invalid, inform user, reset IP variable, and allow them to try again. 
        print("Input IP address " + ip + " is invalid, please try again.")
        ip = ""

# Now that we know we have a valid IP address to query, we can append it to the query URL
queryUrl = queryUrl + str(ip)

# Query greynoise enterprise API and retrieve all data assosciated with host
greynoiseData = requests.get(queryUrl, headers=headers)

# Convery query response into python object so we may more easily reference it's datapoints
# For instance, if we recieved the response:
# {
#   "ip": "8.8.8.8",
#   "seen": false
# }
# Then we could reference the data by calling parsedData.ip to retrieve "8.8.8.8"
parsedData = json.loads(greynoiseData.text, object_hook=
                        lambda d : namedtuple('parsedData', d.keys())
                        (*d.values()))

# print(str(parsedData.ip))
# print(str(parsedData.seen))

if parsedData.seen == False:
    print("IP " + str(ip) + " has not been observed by the GreyNoise sensor network. Please query another IP for more data.")
elif parsedData.seen == True:
    print("This IP has been observed by the GreyNoise sensor network, please choose from the following options to learn more about the IP.")