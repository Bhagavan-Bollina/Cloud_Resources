#!/bin/bash

        #passwordx=$(cat ~/tools/.creds | grep password | awk {'print $3'})

        [ ! -f ~/xcriminal/recon/recondata ] && mkdir ~/xcriminal/recon/recondata
        [ ! -f ~/xcriminal/recon/recondata/$1 ] && mkdir ~/xcriminal/recon/recondata/$1
        [ ! -f ~/xcriminal/recon/recondata/$1/otxurls ] && mkdir ~/xcriminal/recon/recondata/$1/otxurls
        [ ! -f ~/xcriminal/recon/recondata/$1/waybackurls ] && mkdir ~/xcriminal/recon/recondata/$1/waybackurls
        sleep 5


        scanned () {
                cat $1 | sort -u | wc -l
        }

        #message "[%3B]%20Initiating%20scan%20%3A%20$1%20[%3B]"
        date

        echo "[+] AMASS SCANNING [+]"
        if [ ! -z $(which amass) ]; then
                amass enum -active -d $1  -o ~/xcriminal/recon/recondata/$1/$1-amass.txt
                amasscan=`scanned ~/xcriminal/recon/recondata/$1/$1-amass.txt`
                ##message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
                echo "[+] Amass Found $amasscan subdomains"
        else
                #message "[-]%20Skipping%20Amass%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] CHAOS SCANNING [+]"
        if  [ ! -z $(which chaos) ]; then
                 chaos -d $1 -silent -key 50b213913c0d677451de85f36e0cf6abf0ee8c09212bc9ddf6ec3f449dae27b4  -o ~/xcriminal/recon/recondata/$1/$1-chaos.txt
                chaoscan=`scanned ~/xcriminal/recon/recondata/$1/$1-chaos.txt`
                ##message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$1"
                echo "[+] Chaos Found $chaoscan subdomains"
        else
                #message "[-]%20Skipping%20Amass%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] FINDOMAIN SCANNING [+]"
        if [ ! -z $(which findomain) ]; then
                findomain -t $1 -q -u ~/xcriminal/recon/recondata/$1/$1-findomain.txt
                findomainscan=`scanned ~/xcriminal/recon/recondata/$1/$1-findomain.txt`
                #message "Findomain%20Found%20$findomainscan%20subdomain(s)%20for%20$1"
                echo "[+] Findomain Found $findomainscan subdomains"
        else
                #message "[-]%20Skipping%20Findomain%20$findomainscan%20previously%20discovered%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] ASSETFINDER SCANNING [+]"
        if  [ ! -z $(which assetfinder) ]; then
                assetfinder --subs-only $1 >> ~/xcriminal/recon/recondata/$1/$1-assetfinder.txt
                assetfinderscan=`scanned ~/xcriminal/recon/recondata/$1/$1-assetfinder.txt`
                #message "Assetfinder%20Found%20$assetfinderscan%20subdomain(s)%20for%20$1"
                echo "[+] Assetfinder Found $assetfinderscan subdomains"
        else
                #message "[-]%20Skipping%20Findomain%20$findomainscan%20previously%20discovered%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] SUBFINDER SCANNING [+]"
        if [ ! -z $(which subfinder) ]; then
                subfinder -d $1  -silent >> ~/xcriminal/recon/recondata/$1/$1-subfinder.txt
                subfinderscan=`scanned ~/xcriminal/recon/recondata/$1/$1-subfinder.txt`
                #message "SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$1"
                echo "[+] Subfinder Found $subfinderscan subdomains"
        else
                #message "[-]%20Skipping%20Subfinder%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] CRT.SH SCANNING [+]"
        if [ ! -f ~/xcriminal/recon/recondata/$1/$1-crts.txt ]; then
                curl "https://crt.sh/?q=%25.$1&output=json" --silent | jq '.[]|.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u >> ~/xcriminal/recon/recondata/$1/$1-cr
t.txt
                crt=`scanned ~/xcriminal/recon/recondata/$1/$1-crt.txt`
                #message "CRT.SH%20Found%20$crt%20subdomain(s)%20for%20$1"
                echo "[+] CRT.sh Found $crt subdomains"
        else
                #message "[-]%20Skipping%20CRT.SH%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5



        ## Deleting all the results to less disk usage
        cat ~/xcriminal/recon/recondata/$1/$1-amass.txt  ~/xcriminal/recon/recondata/$1/$1-findomain.txt ~/xcriminal/recon/recondata/$1/$1-assetfinder.txt ~/xcriminal/recon/recondata/$
1/$1-subfinder.txt ~/xcriminal/recon/recondata/$1/$1-aquatone.txt  ~/xcriminal/recon/recondata/$1/$1-crt.txt  | sort -uf > ~/xcriminal/recon/recondata/$1/$1-final.txt
        rm ~/xcriminal/recon/recondata/$1/$1-amass.txt ~/xcriminal/recon/recondata/$1/$1-chaos.txt ~/xcriminal/recon/recondata/$1/$1-findomain.txt ~/xcriminal/recon/recondata/$1/$1-ass
etfinder.txt ~/xcriminal/recon/recondata/$1/$1-subfinder.txt ~/xcriminal/recon/recondata/$1/$1-aquatone.txt ~/xcriminal/recon/recondata/$1/$1-crt.txt
        touch ~/xcriminal/recon/recondata/$1/$1-ipz.txt
        sleep 5




        cat ~/xcriminal/recon/recondata/$1/$1-final.txt | sort -u >> ~/xcriminal/recon/recondata/$1/$1-fin.txt
        rm ~/xcriminal/recon/recondata/$1/$1-final.txt && mv ~/xcriminal/recon/recondata/$1/$1-fin.txt ~/xcriminal/recon/recondata/$1/$1-final.txt
        sed -i "s/\\\n/,/g" ~/xcriminal/recon/recondata/$1/$1-final.txt &&  cat ~/xcriminal/recon/recondata/$1/$1-final.txt | grep  -o -E "([a-zA-Z0-9]{1,}\\.){1,}([a-zA-Z0-9]{1,
}\\.[a-zA-Z]{1,})" >> ~/xcriminal/recon/recondata/$1/$1-final1.txt
        mv ~/xcriminal/recon/recondata/$1/$1-final1.txt ~/xcriminal/recon/recondata/$1/$1-final.txt
        all=`scanned ~/xcriminal/recon/recondata/$1/$1-final.txt`
        #message "Almost%20$all%20Collected%20Subdomains%20for%20$1"
        echo "[+] $all collected subdomains"
        sleep 3


        echo "[+] Scanning Alive Hosts [+]"
        if  [ ! -z $(which filter-resolved) ]; then
                cat ~/xcriminal/recon/recondata/$1/$1-final.txt | filter-resolved | httpx -silent -ip -title -status-code >> ~/xcriminal/recon/recondata/$1/$1-alive_with_ip.txt
                cat ~/xcriminal/recon/recondata/$1/$1-alive_with_ip.txt | cut -d " " -f1 >> ~/xcriminal/recon/recondata/$1/$1-alive.txt
                alivesu=`scanned ~/xcriminal/recon/recondata/$1/$1-alive.txt`
                cat ~/xcriminal/recon/recondata/$1/$1-alive_with_ip.txt | cut -d " " -f2 | cut -c 2- | cut -d "]" -f1  >>~/xcriminal/recon/recondata/$1/$1-ipz.txt
                #rm ~/xcriminal/recon/recondata/$1/$1-all.txt
                #message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$1"
                echo "[+] $alivesu alive domains out of $all domains/IPs using filter-resolved"
        else
                #message "[-]%20Skipping%20filter-resolved%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5


        echo "[+] SUBJACK for Subdomain TKO [+]"
        if [ ! -z $(which subjack) ]; then
                wget "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -O ~/tools/fingerprints.json
                subjack -w ~/xcriminal/recon/recondata/$1/$1-final.txt -a -timeout 15 -c ~/tools/fingerprints.json  -m -o ~/xcriminal/recon/recondata/$1/$1-subtemp.txt
                subjack -w ~/xcriminal/recon/recondata/$1/$1-final.txt -a -timeout 15 -c ~/tools/fingerprints.json  -m -ssl -o ~/xcriminal/recon/recondata/$1/$1-subtmp.txt
                subjack -w ~/xcriminal/recon/recondata/$1/$1-final.txt -a -timeout 15 -c /home/sai/go/src/github.com/haccer/subjack/fingerprints.json -m -ssl >> ~/xcriminal/recon
/recondata/$1/$1-subtmp.txt
                bash ec2takeover ~/xcriminal/recon/recondata/$1/$1-final.txt ~/xcriminal/recon/recondata/$1/$1-subjack.txt
                cat ~/xcriminal/recon/recondata/$1/$1-subtemp.txt ~/xcriminal/recon/recondata/$1/$1-subtmp.txt | sort -u > ~/xcriminal/recon/recondata/$1/$1-subjack.txt
                rm ~/xcriminal/recon/recondata/$1/$1-subtemp.txt ~/xcriminal/recon/recondata/$1/$1-subtmp.txt
                #message "subjack%20scanner%20done%20for%20$1"
                echo "[+] Subjack scanner is done"
        else
                #message "[-]%20Skipping%20subjack%20Scanning%20for%20$1"
                echo "[!] Skipping ..."
        fi
        sleep 5

        echo "[+] Gathering IP's [+]"
        amass enum -active -d $1 -ip | cut -d " " -f2 >> ~/xcriminal/recon/recondata/$1/$1-ipz.txt
        #shodan search --fields ip_str $1 >> ~/xcriminal/recon/recondata/$1/$1-ipz.txt
        for i in $(cat ~/xcriminal/recon/recondata/$1/$1-final.txt); do dig +short $i|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1 ;done >> ~/xcriminal/recon/recondata/$1/$
1-ipz.txt
        cat ~/xcriminal/recon/recondata/$1/$1-ipz.txt | grep -o -E "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" |
 sort -u >> ~/xcriminal/recon/recondata/$1/$1-ips.txt
        rm  ~/xcriminal/recon/recondata/$1/$1-ipz.txt

        echo "[+] Starting Nuclei Scanning"
        mkdir ~/xcriminal/recon/recondata/$1/nuclei_op
        cd ~/tools/nuclei-templates/
        git pull
        cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt| nuclei  -t ~/tools/nuclei-templates/cves/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/cves.txt
        cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt|nuclei -t ~/tools/nuclei-templates/files/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/files.txt
        cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt|nuclei  -t ~/tools/nuclei-templates/panels/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/panels.txt
        # cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt|nuclei  -t ~/tools/nuclei-templates/security-misconfiguration/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/securi
ty-misconfiguration.txt
        #nuclei ~/xcriminal/recon/recondata/$1/$1-alive.txt -t "/tools/nuclei-templates/technologies/*.yaml" -c 60 -o nuclei_op/technologies.txt
        # cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt|nuclei  -t ~/tools/nuclei-templates/tokens/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/tokens.txt
        cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt| nuclei  -t ~/tools/nuclei-templates/vulnerabilities/ -c 60 -o ~/xcriminal/recon/recondata/$1/nuclei_op/vulnerabilities.t
xt

        #message "Scanner%20Done%20for%20$1"
        date

        echo "[+] Starting CRLF Scanner"
        cat ~/xcriminal/recon/recondata/$1/$1-alive.txt | crlfuzz -o ~/xcriminal/recon/recondata/$1/$1-crlf_output.txt

        # echo "[+] Get urls from otx"
        # #for i in $(cat /xcriminal/recon/recondata/$1/$1-final.txt);do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$1?limit=100&page=1" | grep "\burl
\b" | gron --ungron | jq | grep "url" | cut -d "\"" -f4 | unew -combine; done >> ~/xcriminal/recon/recondata/$1/otxurls/$1-otxurls.txt
        # for sub in $(cat ~/xcriminal/recon/recondata/$1/$1-final.txt);do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\
burl\b" | gron --ungron | jq |egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u >> ~/xcriminal/recon/recondata/$1/otxurls/$1-otxurls.txt   ;done

        echo "[+] Get urls from GAU"
        cat ~/xcriminal/recon/recondata/$1/$1-alive.txt | gau |egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'| httpx -silent -status-code |  egrep -v '(401|402|400|403|404|
501|502|503|504|505)'| unew  >> ~/xcriminal/recon/recondata/$1/otxurls/$1-gau_out.txt
        cat ~/xcriminal/recon/recondata/$1/otxurls/$1-gau_out.txt ~/xcriminal/recon/recondata/$1/otxurls/$1-otxurls.txt | unew  >> ~/xcriminal/recon/recondata/$1/$1-urls.txt
        # rm ~/xcriminal/recon/recondata/$1/otxurls/$1-gau_out.txt ~/xcriminal/recon/recondata/$1/otxurls/$1-otxurls.txt


        #meg ~/xcriminal/recon/recondata/$1/$1-urls.txt ~/xcriminal/recon/recondata/$1/$1-meg_out.txt
        echo "[+] Checking for sensitive tokens"
        cat ~/xcriminal/recon/recondata/$1/$1-urls.txt|nuclei  -t ~/tools/nuclei-templates/tokens/ -c 60 >> ~/xcriminal/recon/recondata/$1/nuclei_op/tokens.txt
        # echo "[+] Running Github Recon"
        # cd ~/xcriminal/xcriminal_recon/gitGraber
        # /usr/bin/python3 gitGraber.py -k wordlists/keywords.txt -q \"$1\" -s
        # cd ~/xcriminal/recon/

        echo "[+] Starting HTTP Request Smuggler"
        cd ~/tools/smuggler/
        cat  ~/xcriminal/recon/recondata/$1/$1-alive.txt | python3 smuggler.py -l  ~/xcriminal/recon/recondata/$1/$1-request-smuggling-out.txt
        cd ~/xcriminal/recon/
        echo "[+] Done scanner :):" $1
