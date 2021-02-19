# Tempus
Project Tempus is a recon automation script for bug bounty hunters and penetration testers to assist in the 1st phase of the cyber kill chain which is reconnaissance allowing the tester to spend more time on hacking and less time on the tedious reconnaissance phase.  Tempus can run on a cron job over night so fresh scan data is ready everyday allowing the tester to have a updated overview of the target web application with live updates via a telegram bot that will alert the tester of new endpoints and potentially vulnerable targets.

# Version: Alpha 1.0

# Features

Tempus does almost everything using passive and active reconnaissance for web applications such as:

* Passive subdomain gathering
* Active subdomain gathering
* Certificate transperancy 
* DNS bruteforcing
* Pulling data from 3rd party sources such as project discovery
* Probing for alive subdomains
* Gathering IP addresses from subdomains and ASN's
* Portscanning on IP addresses
* Directory and file bruteforcing
* Scanning for virtual hosts
* Scanning for AWS S3 buckets
* Scanning for known CVE's on IP space
* Checking for subdomain takeovers
* Tempus also has a telegram bot feature allowing for alerts to be sent to the user regarding scans and data such as new subdomains.

# Future features to be implemented
* Putting all data into a MySQL database
* A diff function to compare new scan results from last scan to get new data
* Replacing the telegram bot with a slack bot and adding new alerts for new data and potentialy vulnerable endpoints
* Javascript monitoring with JSmon
* Creating custom wordlists for the target from waybackmachine results aswell as scan results
* Parsing JS files for secrets such as api keys and tokens
* Using axiom in conjuction with massdns and hakrawler to make script faster
* input options for threads and the axiom number of droplets in fleet
* masscan to check for open ports then nmap for service enumeration to make script faster  

# Setup
