# greynoise-test
CLI based Greynoise API query tool to gather data on target IP addresses

Functions
---------
1) List IP Visibility data (i.e. IP, first and last seen date, OS)
2) List IP VPN data (If IP is known part of VPN service, and name of service if so, if it is a tor exit node, etc.)
3) List geographic IP data (Country, Region, City, Category (isp, mobile, edu, etc))
4) List IP threat data (Classification, actor, tags, spoofable)
5) List IP Metadata (RDNS Pointer, ASN, country code)

TODO
----
1) Add function calls after successful malicious IP lookup
2) Allow user to enter new query IP without restarting program after entering valid IP

KNOWN BUGS
----------
1) Entering a second IP address after the first one evaluated always returns an invalid IP error