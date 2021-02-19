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
else
        echo "Target is $input"
fi
}

source ~/.profile	


help(){
	echo "Usage: ./autorecon -d example.com"
}


main(){
	
	# RENAME AUTORECON AND REPLACE ALL DIRS AND FILES WITH NAME
	# CLEAN UP DIRECTORY AND FILE STRUCTURE
	clear
	check $@

	#making all directories and outfiles needed
	mkdir ./autorecon-out/$d/javascript
	touch ./autorecon-out/$d/javascript/js-api-endpoinds.txt
	touch ./autorecon-out/$d/javascript/hakcrawler-jsfiles.txt
	touch ./autorecon-out/$d/javascript/js-params.txt
	touch ./autorecon-out/$d/javascript/js-links.txt

	mkdir ./autorecon-out/$d/hosts
	touch ./autorecon-out/$d/hosts/ips.txt

	mkdir ./autorecon-out/$d/subdomains
	touch ./autorecon-out/$d/subdomains/massdns-$d.txt
	touch ./autorecon-out/$d/subdomains/crtsh-$d.txt
	touch ./autorecon-out/$d/subdomains/certspotter-$d.txt
	touch ./autorecon-out/$d/subdomains/amass-passive-$d.txt
	touch ./autorecon-out/$d/subdomains/amass-brute-$d.txt
	touch ./autorecon-out/$d/subdomains/projectdiscovery-$d.txt
	touch ./autorecon-out/$d/subdomains/altdns-perm-subs.txt
	touch ./autorecon-out/$d/subdomains/all-subdomains.txt
	touch ./autorecon-out/$d/subdomains/alive-subdomains.txt
	touch ./autorecon-out/$d/subdomains/altdns-perm-subs.txt

	mkdir ./autorecon-out/$d/dirs
	touch ./autorecon-out/$d/dirs/alive-dirsearch.txt

	mkdir ./autorecon-out/$d/scans/
	touch ./autorecon-out/$d/scans/cves-$d.txt
	touch ./autorecon-out/$d/scans/takeovers-$d.txt
	touch ./autorecon-out/$d/scans/s3buckets.txt
	touch ./autorecon-out/$d/scans/vhosts.txt


	#function calls to run recon on target domain
	subdomaingathering $d
	cleanup $d
	dirbusting $d
	hosts $d
	portscanning $d
	jsfiles $d
	scans $d

	#calls telegram bot at the end to send message when recon is complete
	telegrambot

	stty sane
  	tput sgr0
}


subdomaingathering(){
	echo "scraping crt.sh and certspotter for subdomains"
	#scraping subdomains from crtsh and certspotter
	crtsh $d > ~/autorecon-out/$domain/subdomains/crtsh-$d.txt
	certspotter $d > ~/autorecon-out/$domain/subdomains/certspotter-$d.txt


	echo "running amass passive and active bruteforce scans"
	#amass recursively passive and bruteforce scanning on subdomains
	amass enum -passive -d $d -o ~/autorecon-out/$d/subdomains/amass-passive-$d.txt
	amass enum -brute -d $d -rf ~/wordlists/DNS/dns-resolvers.txt -w ~/wordlists/subdomains.txt -o ~/autorecon-out/$d/subdomains/amass-brute-$d.txt

	#ADD MASSDNS WITH AXIOM
	echo "DNS bruteforcing with massdns"
	cd ~/tools/massdns
	rm all.txt
	#gets jhaddix all.txt and appends tld to each line in list of DNS resolvers
	wget https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
	sed -e 's/$/$d/' -i all.txt
	#runs massdns and uses DNS resolution to get all subdomains and filters data
	./bin/massdns -r lists/resolvers.txt -t CNAME all.txt -o S > results
	cut -d' ' -f -1 results >> tmp.txt
	sed 's/.$//' tmp.txt >> ~/autorecon-out/$d/subdomains/massdns-$d.txt
	rm tmp.txt


	echo "scraping subdomains from projectdiscovery"
	#getting all data from chaos poject discovery subdomains 
	chaos -d $d -o ~/autorecon-out/$d/subdomains/projectdiscovery-$d.txt

}


cleanup(){
	echo "cleaning up data collected and sorting it into files"
	cd ~/autorecon-out/$d/subdomains
	#sorts all files by uniqe subdomains and puts them in once file
	sort -u massdns-$d.txt crtsh-$d.txt certspotter-$d.txt amass-passive-$d.txt amass-brute-$d.txt projectdiscovery-$d.txt > all-subdomains.txt

	#probes all subdomains to test for alive domains
	cat all-subdomains.txt | httprobe -c 100 > alive-subdomains.txt
	cat alive-subdomains.txt | grep https | cut -c 9- > all-alive.txt

	rm alive-subdomains.txt
}


hosts(){
	echo "getting all webserver IP address's from collected subdomains"
	#getting all alive webservers
	for i in $(cat ~/autorecon-out/$d/subdomains/all-subdomains.txt); do
		dig +short $i | sort -u >> ~/autorecon-out/$d/hosts/dig-ips.txt
	done

	#cleans up file to get all uniqe webservers
	grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' ~/autorecon-out/$d/hosts/dig-ips.txt > ~/autorecon-out/$d/hosts/ipaddresses.txt
	cat ipaddresses.txt | sort -u > ~/autorecon-out/$d/hosts/ips.txt
	rm ~/autorecon-out/$d/hosts/ipaddresses.txt
	rm ~/autorecon-out/$d/hosts/dig-ips.txt
}


portscanning(){
	echo "scanning all webservers with nmap"
	# starts up axiom fleet of droplets then runs nmapx on all ips to port scan
	# then output to nmap-bootstrap-xsl for user to start python3 simpleHTTPserver and view web report
	axiom-fleet worker -i=15
	axiom-select 'worker*'
	axiom-scan ~/autorecon-out/$d/hosts/ips.txt -m nmapx -p- -sC -sV -T4 -oA scanme --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl scanme.nmap.org scanme2.nmap.org
	axiom-rm 'worker*' -f
}


dirbusting(){
	echo "dirbusting with dirsearch to get all directories"
	cd ~/tools/dirsearch
	# recursively scan for all dirs on alive subdomains
	for i in $(cat ~/autorecon-out/$d/subdomains/all-alive.txt); do 
		./dirsearch.py -t 200 -r -R 5 --subdirs -u $i -e php,html,txt,xml,sql,asp,aspx,log,exe,bak,zip,jar,jsp -w ~/wordlists/web-dirs/dir-big.txt --simple-report=~/autorecon-out/$d/dirs/$i.txt
	done
}


jsfiles(){
	echo "Gathering JS files"
	#getting js files from hakcrawler
	for i in $(cat ~/autorecon-out/$d/subdomains/all-alive.txt); do
		hakcrawler -url $i -js -plain | sort -u >> ~/autorecon-out/$d/javascript/hakcrawler-jsfiles.txt
	done

	#gathering API endpoints from JS files with regex filter
	cat ~/autorecon-out/$d/javascript/hakcrawler-jsfiles.txt | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | sort -u >> ~/autorecon-out/$d/javascript/js-api-endpoinds.txt

	# finding hidden get params in JS files
	for i in $(cat ~/autorecon-out/$d/subdomains/all-alive.txt); do
		assetfinder $i | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars" >> ~/autorecon-out/$d/javascript/js-params.txt; done
	done

	# finding links in js files with linkfinder
	cd ~/tools/linkfinder/
	for i in $(cat ~/autorecon-out/$d/javascript/hakcrawler-jsfiles.txt); do 
		python3 linkfinder.py -i $i -o cli >> ~/autorecon-out/$d/javascript/js-links.txt
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
	axiom-scan ~/autorecon-out/$d/hosts/ips.txt -m nuclei -silent -t cves/ -o ~/autorecon-out/$d/scans/cves-$d.txt
	axiom-scan ~/autorecon-out/$d/subdomains/all-alive.txt -m nuclei -silent -t takeovers/ -o ~/autorecon-out/$d/scans/takeovers-$d.txt
	axiom-rm 'worker*' -f

	# scanning for AWS S3 buckets on all alive subdomains
	# can use aws cli when testing buckets
	cd ~/tools/S3scanner/
	python3 s3scanner.py --dump ~/autorecon-out/$d/subdomains/all-alive.txt -o ~/autorecon-out/$d/scans/s3buckets.txt

	# using hosthunter to scan for virtual hosts on alive subdomains
	cd ~/tools/HostHunter/
	python3 hosthunter.py ~/autorecon-out/$d/hosts/ips.txt --bing -f txt -o ~/autorecon-out/$d/scans/vhosts.txt
}


telegrambot(){
	import requests

	def telegram_bot_sendtext(bot_message):
	    #here i enter my telegram bot token and chatID
	    bot_token = '1516898483:AAGXQjKTHmpWcPo-OMfJ8koRjz4f-RE00aU'
	    bot_chatID = '1670316277'
	    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

	    response = requests.get(send_text)

	    return response.json()
	    
	#here is the message the bit will send
	test = telegram_bot_sendtext("Recon scans complete")
	print(test)
}

# all arguments passed to script now passed to main function
main $@
