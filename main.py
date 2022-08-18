import os
import json
import requests
import ipaddress
from ast import parse
from collections import namedtuple
from dotenv import load_dotenv, find_dotenv

# Search for and load .env file to access environment variables
load_dotenv(find_dotenv())

# Base IP will need to be appended to query URL before query is sent
ip = ""

# Define primary functionality loop
def main(ip):
    # Request IP to be queried from user as many times as necessary to get valid IP address
    while ip == "":
        queryUrl = "https://api.greynoise.io/v2/noise/context/"

        try:
            # This checks to make sure the input IP is valid. If it is not, it will throw a ValueError
            ip = ipaddress.ip_address(input("Please input the IP address of the device you would like to query:"))
        except:
            # If IP provided was invalid, inform user, reset IP variable, and allow them to try again. 
            print("Input IP address " + ip + " is invalid, please try again.")
            ip = ""
            continue

        # Now that we know we have a valid IP address to query, we can append it to the query URL
        queryUrl = queryUrl + str(ip)

        # Query greynoise enterprise API and retrieve all data assosciated with host
        greynoiseData = query(queryUrl)

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

        # If the query returns an error rather than valid data, tell user and ask for valid IP
        if hasattr(parsedData, "error"):
            print("Error: " + parsedData.error)
            print("Please try again.")
            ip = ""
            continue

        # If GreyNoise hasn't seen this IP, it won't have data for us. Send user back to try another IP.
        if parsedData.seen == False:
            print("IP " + str(ip) + " has not been observed by the GreyNoise sensor network. Please query another IP for more data.")
            ip = ""
            continue
        # If GreyNoise HAS seen this IP, give the user options to dig into the discovered data
        elif parsedData.seen == True:
            print("This IP has been observed by the GreyNoise sensor network, please choose from the following options to learn more about the IP.")

            evaluateMaliciousIp(parsedData)
            # If user gets to below line of code, they have selected option 6 to evaluate a new IP. Reset the IP to blank and restart the loop
            ip = ""

def query(url):
    # Set request headers, ensuring data recieved is JSON and storing the key to the API
    # Note, please don't use API key for evil :)
    headers = {
        "Accept": "application/json",
        "key": os.getenv('API_KEY')
    }

    # Send HTTP Get request to target URL with given parameters
    data = requests.get(url, headers=headers)

    # Return the resulting JSON object
    return data

# Print all selection options
def listSelections():
    print("1) List IP Visibility data (i.e. first and last seen date, OS)")
    print("2) List IP VPN data (If IP is known part of VPN service, and name of service if so, if it is a tor exit node, etc.)")
    print("3) List geographic IP data (Country, Region, City, Category (isp, mobile, edu, etc))")   
    print("4) List IP threat data (Classification, actor, tags, spoofable)")
    print("5) List IP Metadata (RDNS Pointer, ASN, country code, port)")
    print("6) Quick Check IP address")
    print("7) Evaluate another IP address")
    print("8) End program")

def quickCheck(ip):
    queryUrl = "https://api.greynoise.io/v2/noise/quick/" + str(ip)
    greynoiseData = query(queryUrl)

    # Convery query response into python object so we may more easily reference it's datapoints
    parsedData = json.loads(greynoiseData.text, object_hook=
                            lambda d : namedtuple('parsedData', d.keys())
                            (*d.values()))

    # If the query returns an error rather than valid data, tell user and ask for valid IP
    if hasattr(parsedData, "error"):
        print("Error: " + parsedData.error)
        print("Please try again.")
        return

    print("IP: " + parsedData.ip)
    # Object code reference table can be found here: https://docs.greynoise.io/reference/quickcheck-1
    print("Object Code: " + parsedData.code)
    print("Noise: " + str(parsedData.noise))
    print("RIOT (Rule it out): " + str(parsedData.riot))

# Define function/s which evaluate a malicious IP address
def evaluateMaliciousIp(parsedGnData):
    selection = ""

    while selection == "":
        # Print program options for user
        listSelections()

        # Get user input. If valid, return requested data, if not, have them enter another selection.
        selection = input()

        # 1) List IP Visibility data (i.e. first and last seen date, OS)
        if selection == "1":
            print("IP: " + parsedGnData.ip)
            print("First seen: " + str(parsedGnData.first_seen))
            print("Last seen: " + str(parsedGnData.last_seen))
            print("Operating System: " + parsedGnData.metadata.os)
            input("Hit enter to select another option.")
        # 2) List IP VPN data (If IP is known part of VPN service, and name of service if so, if it is a tor exit node, etc.)
        elif selection == "2":
            print("IP: " + parsedGnData.ip)
            print("IP is assosciated with VPN Service: " + str(parsedGnData.vpn))
            print("VPN Service assosciated with IP: " + parsedGnData.vpn_service)
            print("TOR: " + str(parsedGnData.metadata.tor))
            input("Hit enter to select another option.")
        # 3) List geographic IP data (Country, Region, City, Category (isp, mobile, edu, etc))
        elif selection == "3":
            print("IP: " + parsedGnData.ip)
            print("Country: " + parsedGnData.metadata.country)
            print("Region: " + parsedGnData.metadata.region)
            print("City: " + parsedGnData.metadata.city)
            print("Category: " + parsedGnData.metadata.category)
            input("Hit enter to select another option.")
        # 4) List IP threat data (Classification, actor, tags, spoofable)
        elif selection == "4":
            print("IP: " + parsedGnData.ip)
            print("Classification: " + parsedGnData.classification)
            print("Actor: " + parsedGnData.actor)
            print("Tags: " + str(parsedGnData.tags))
            print("Spoofable: " + str(parsedGnData.spoofable))
            input("Hit enter to select another option.")
        # 5) List IP Metadata (RDNS Pointer, ASN, country code)
        elif selection == "5":
            print("IP: " + parsedGnData.ip)
            print("RDNS Pointer: " + parsedGnData.metadata.rdns)
            print("ASN: " + parsedGnData.metadata.asn)
            print("Country Code: " + parsedGnData.metadata.country_code)
            input("Hit enter to select another option.")
        elif selection == "6":
            quickCheck(parsedGnData.ip)
            input("Hit enter to select another option.")
        elif selection == "7":
            # Allow main() function to continue
            return
        elif selection == "8":
            # End program
            exit()
        else:
            # Invalid input, reset selection and restart loop
            print("You have input an invalid selection, please try again")
        selection = ""
        continue

main(ip)