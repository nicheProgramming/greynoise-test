# GreyNoise API query script
CLI based Greynoise API query tool to gather data on target IP addresses

Functions
---------
1) List IP Visibility data (i.e. IP, first and last seen date, OS)
2) List IP VPN data (If IP is known part of VPN service, and name of service if so, if it is a tor exit node, etc.)
3) List geographic IP data (Country, Region, City, Category (isp, mobile, edu, etc))
4) List IP threat data (Classification, actor, tags, spoofable)
5) List IP Metadata (RDNS Pointer, ASN, country code)
6) Quick Check IP address

To-Do
----


Known bugs
----------


Test IPs
- Malicious
    -96.18.5.174
    -77.120.154.110
- Safe
    -1.1.1.1
    -8.8.8.8