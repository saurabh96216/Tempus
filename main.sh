#!/bin/bash

check(){
local OPTIND opt i
while getopts 'd:h' opt; do
        case $opt in
                d) input="$OPTARG";;
                h) help ;;
                \?) help;exit 1 ;;
        esac
done
shift $((OPTIND -1))
#checks if target domain is entered with -d
if [ "$input" = "" ]
then
        echo "no target domain was selected"
        exit
else
        echo "Target is $input"
        mkdir tempus
fi
}

source ~/.profile	


help(){
	echo "Usage: ./tempus -d example.com"
}


main(){
	clear
	check $@

	#making all directories and outfiles needed
	mkdir ./tempus/$d/javascript
	touch ./tempus/$d/javascript/js-api-endpoinds.txt
	touch ./tempus/$d/javascript/hakcrawler-jsfiles.txt
	touch ./tempus/$d/javascript/js-params.txt
	touch ./tempus/$d/javascript/js-links.txt

	mkdir ./tempus/$d/hosts
	touch ./tempus/$d/hosts/ips.txt

	mkdir ./tempus/$d/subdomains
	touch ./tempus/$d/subdomains/massdns-$d.txt
	touch ./tempus/$d/subdomains/crtsh-$d.txt
	touch ./tempus/$d/subdomains/certspotter-$d.txt
	touch ./tempus/$d/subdomains/amass-passive-$d.txt
	touch ./tempus/$d/subdomains/amass-brute-$d.txt
	touch ./tempus/$d/subdomains/projectdiscovery-$d.txt
	touch ./tempus/$d/subdomains/altdns-perm-subs.txt
	touch ./tempus/$d/subdomains/all-subdomains.txt
	touch ./tempus/$d/subdomains/alive-subdomains.txt
	touch ./tempus/$d/subdomains/altdns-perm-subs.txt

	mkdir ./tempus/$d/dirs
	touch ./tempus/$d/dirs/alive-dirsearch.txt

	mkdir ./tempus/$d/scans/
	touch ./tempus/$d/scans/cves-$d.txt
	touch ./tempus/$d/scans/takeovers-$d.txt
	touch ./tempus/$d/scans/s3buckets.txt
	touch ./tempus/$d/scans/vhosts.txt


	#function calls to run recon on target domain
	subdomaingathering $d
	cleanup $d
	dirbusting $d
	hosts $d
	portscanning $d
	jsfiles $d
	scans $d

	#calls slack bot to send alerts
	slackbot $d
	diff $d

	stty sane
  	tput sgr0
}


subdomaingathering(){
	echo "scraping crt.sh and certspotter for subdomains"
	#scraping subdomains from crtsh and certspotter
	crtsh $d > ~/tempus/$domain/subdomains/crtsh-$d.txt
	certspotter $d > ~/tempus/$domain/subdomains/certspotter-$d.txt


	echo "running amass passive and active bruteforce scans"
	#amass recursively passive and bruteforce scanning on subdomains
	amass enum -passive -d $d -o ~/tempus/$d/subdomains/amass-passive-$d.txt
	amass enum -brute -d $d -rf ~/wordlists/DNS/dns-resolvers.txt -w ~/wordlists/subdomains.txt -o ~/tempus/$d/subdomains/amass-brute-$d.txt


	echo "DNS bruteforcing with massdns"
	cd ~/tools/massdns
	rm all.txt
	#gets jhaddix all.txt and appends tld to each line in list of DNS resolvers
	wget https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
	cat all.txt | while read line; do echo ${line}$d; done
	#runs massdns and uses DNS resolution to get all subdomains and filters data
	./bin/massdns -r lists/resolvers.txt -t CNAME all.txt -o S > results
	cut -d' ' -f -1 results >> tmp.txt
	sed 's/.$//' tmp.txt >> ~/tempus/$d/subdomains/massdns-$d.txt
	rm tmp.txt


	echo "scraping subdomains from projectdiscovery"
	#getting all data from chaos poject discovery subdomains 
	chaos -d $d -o ~/tempus/$d/subdomains/projectdiscovery-$d.txt

}


cleanup(){
	echo "cleaning up data collected and sorting it into files"
	cd ~/tempus/$d/subdomains
	#sorts all files by uniqe subdomains and puts them in one file
	sort -u massdns-$d.txt crtsh-$d.txt certspotter-$d.txt amass-passive-$d.txt amass-brute-$d.txt projectdiscovery-$d.txt > all-subdomains.txt

	#probes all subdomains to test for alive domains
	cat all-subdomains.txt | httprobe -c 100 > alive-subdomains.txt
	cat alive-subdomains.txt | grep https | cut -c 9- > all-alive.txt

	rm alive-subdomains.txt
}


hosts(){
	echo "getting all webserver IP address's from collected subdomains"
	#getting all alive webservers
	for i in $(cat ~/tempus/$d/subdomains/all-subdomains.txt); do
		dig +short $i | sort -u >> ~/tempus/$d/hosts/dig-ips.txt
	done

	#cleans up file to get all uniqe webservers
	grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' ~/tempus/$d/hosts/dig-ips.txt > ~/tempus/$d/hosts/ipaddresses.txt
	cat ipaddresses.txt | sort -u > ~/tempus/$d/hosts/ips.txt
	rm ~/tempus/$d/hosts/ipaddresses.txt
	rm ~/tempus/$d/hosts/dig-ips.txt
}


portscanning(){
	echo "scanning all webservers with nmap"
	# starts up axiom fleet of droplets then runs nmapx on all ips to port scan
	# then output to nmap-bootstrap-xsl for user to start python3 simpleHTTPserver and view web report
	axiom-fleet worker -i=15
	axiom-select 'worker*'
	axiom-scan ~/tempus/$d/hosts/ips.txt -m nmapx -p- -sC -sV -T4 -oA scanme --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl scanme.nmap.org scanme2.nmap.org
	axiom-rm 'worker*' -f
}


dirbusting(){
	echo "dirbusting with dirsearch to get all directories"
	cd ~/tools/dirsearch
	# recursively scan for all dirs on alive subdomains
	for i in $(cat ~/tempus/$d/subdomains/all-alive.txt); do 
		./dirsearch.py -t 200 -r -R 5 --subdirs -u $i -e php,html,txt,xml,sql,asp,aspx,log,exe,bak,zip,jar,jsp -w ~/wordlists/web-dirs/dir-big.txt --simple-report=~/tempus/$d/dirs/$i.txt
	done
}


jsfiles(){
	echo "Gathering JS files"
	#getting js files from hakcrawler
	for i in $(cat ~/tempus/$d/subdomains/all-alive.txt); do
		hakcrawler -url $i -js -plain | sort -u >> ~/tempus/$d/javascript/hakcrawler-jsfiles.txt
	done

	#gathering API endpoints from JS files with regex filter
	cat ~/tempus/$d/javascript/hakcrawler-jsfiles.txt | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | sort -u >> ~/tempus/$d/javascript/js-api-endpoinds.txt

	# finding hidden get params in JS files
	for i in $(cat ~/tempus/$d/subdomains/all-alive.txt); do
		assetfinder $i | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars" >> ~/tempus/$d/javascript/js-params.txt; done
	done

	# finding links in js files with linkfinder
	cd ~/tools/linkfinder/
	for i in $(cat ~/tempus/$d/javascript/hakcrawler-jsfiles.txt); do 
		python3 linkfinder.py -i $i -o cli >> ~/tempus/$d/javascript/js-links.txt
	done 
}


scans(){
	echo "scanning all subdomains from target"
	# creates fleet of 15 droplets then updates templates for nuclei then runs
	# nuclei scans for cve checking on alive ips and subdomain takeovers on alive subdomains
	# then deletes the fleet
	axiom-fleet worker -i=15
	axiom-select 'worker*'
	axiom-exec 'nuclei -update-templates'
	axiom-scan ~/tempus/$d/hosts/ips.txt -m nuclei -silent -t cves/ -o ~/tempus/$d/scans/cves-$d.txt
	axiom-scan ~/tempus/$d/subdomains/all-alive.txt -m nuclei -silent -t takeovers/ -o ~/tempus/$d/scans/takeovers-$d.txt
	axiom-rm 'worker*' -f

	# scanning for AWS S3 buckets on all alive subdomains
	# can use aws cli when testing buckets
	cd ~/tools/S3scanner/
	python3 s3scanner.py --dump ~/tempus/$d/subdomains/all-alive.txt -o ~/tempus/$d/scans/s3buckets.txt

	# using hosthunter to scan for virtual hosts on alive subdomains
	cd ~/tools/HostHunter/
	python3 hosthunter.py ~/tempus/$d/hosts/ips.txt --bing -f txt -o ~/tempus/$d/scans/vhosts.txt
}


slackbot(){
	#slack alert for complete scan and date scan was completed
	data=$(date)
	curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Recon scans are complete for: $data\"}" https://hooks.slack.com/services/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
	
	#slack alert for number of alive subdomains
	typeset -i alivesubs
	alivesubs=$(sudo cat ~/tempus/$d/subdomains/all-alive.txt | wc -l)
	message1=$(echo $alivesubs)
	curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Number of alive subdomains: $message1\"}" https://hooks.slack.com/services/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

	#slack alert for number of ip addresses
	typeset -i ips
	ips=$(sudo cat ~/tempus/$d/hosts/ips.txt | wc -l)
	message2=$(echo $ips)
	curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Number of ip addresses: $message2\"}" https://hooks.slack.com/services/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
}


diff(){
	# diff function to compare results from last scan with new scan and get new endpoints
	# moves recon scan to directory with date scan was conducted
	dirname=$(date | cut -d' ' -f -3 | sed 's/ /-/g')
	mkdir $dirname
	mv tempus ~/$dirname

	# from here the tester can manually compare scan results from new and old scans

}

# all arguments passed to script now passed to main function
main $@
