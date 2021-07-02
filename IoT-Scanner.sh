#!/bin/bash

# Install dependant apps
sudo apt install nmap -y -q > /dev/null

# Define Color Variables
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m'
NCB='\033[1m'


clear

PS3='Please enter your choice: ' #Sets PS3 prompt
options=("Start Scan" "Previous Scan Results" "Quit")
select opt in "${options[@]}"
do
case $opt in
"Start Scan")
	clear
	PS3='Please enter your choice: ' #Sets PS3 prompt
	optionss=( "User friendly Scan" "Verbose Scan" "Quit")
	select opt in "${optionss[@]}"
	do
	case $opt in

	"User friendly Scan"  )
	echo
	rm -f SSH-Credentials.txt
	rm -f Telnet-Credentials.txt

	clear
	

	ip a | grep -w "inet" | tail +2 | awk '{print $2}' > ips.txt # This gets the IP along with the subnet and is put into ips.txt for use with nmap.

	nmap -oG lips.txt -sP -iL ips.txt > /dev/null                # Nmap then scans for active IP addresses and saves them into l(ive)ips.txt.

	grep Host lips.txt | awk '{print $2}' > temp.txt; mv temp.txt lips.txt #Extracting the IP addresses and saving them.

	ips="$(wc lips.txt | awk '{print $1}')" # This calculates the number of live devices.
	printf "%bTesting $ips live device/s on the network\n" "$GREEN"
	printf "%b\n" "$NC"

	#Creating username and password file.
	touch user.txt; echo admin >> user.txt; echo root >> user.txt; echo ubnt >> user.txt; echo support >> user.txt; echo service >> user.txt; echo guest >> user.txt; echo root >> user.txt 
	touch pass.txt; echo admin >> pass.txt; echo root >> pass.txt; echo password >> pass.txt; echo guest >> pass.txt; echo service >> pass.txt; echo guest >> pass.txt; echo toor >> pass.txt

	open=$(nmap -iL lips.txt -p 23 | grep -E 'open' | awk '{print $2}' | wc | awk '{print $1}') # Finds which live IPs have port 23 (Telnet) open.

	ips=$(cat 'lips.txt')


	for ip in $ips;  

	do

	test=$(nmap "$ip" -p 23 | grep -E 'open|closed' | awk '{print $2}')


		if [[ $test = 'open' ]]; then	

				# Runs Nmap bruteforce script on IPs with port 23 open.								
				var=$(nmap -oX Telnet-Credentials.xml -p 23 --script telnet-brute --script-args userdb=user.txt,passdb=pass.txt,telnet-brute.timeout=8s "$ip" | grep -E 'Valid' | awk '{print $4}')

				user=($(grep -o -P '(?<=username">).*(?=</elem>)' Telnet-Credentials.xml)) # Pulls the username out of the results.
				pass=($(grep -o -P '(?<=password">).*(?=</elem>)' Telnet-Credentials.xml)) # Pulls the password out of the results.	

			if [[ $var = *Valid* ]]; then

				echo "The telnet credentials for $ip are:" >> Telnet-Credentials.txt 

				for i in "${!user[@]}"; do # Takes the index of $user and prints out seqentially $user & $pass

				printf "%s : %s\n\n" "${user[i]}" "${pass[i]}" >> Telnet-Credentials.txt
				
				done

			fi
		fi

	done


	open=$(nmap -iL lips.txt -p 22 | grep -E 'open' | awk '{print $2}' | wc | awk '{print $1}') # Finds which live IPs have port 22 (SSH) open.

	for ip in $ips;  do

	test=$(nmap "$ip" -p 22 | grep -E 'open|closed' | awk '{print $2}')


		if [[ $test = 'open' ]]; then	

		
				# Runs Nmap bruteforce script on IPs with port 22 open.								
				var=$(nmap -oX SSH-Credentials.xml -p 22 --script ssh-brute --script-args userdb=user.txt,passdb=pass.txt,telnet-brute.timeout=8s "$ip" | grep -E 'Valid' | awk '{print $4}')

				user=($(grep -o -P '(?<=username">).*(?=</elem>)' Telnet-Credentials.xml)) # Pulls the username out of the results.
				pass=($(grep -o -P '(?<=password">).*(?=</elem>)' Telnet-Credentials.xml)) # Pulls the password out of the results.

				if [[ $var = *Valid* ]]; then
						
				echo "The SSH credentials for $ip are:" >> SSH-Credentials.txt

				for i in "${!user[@]}"; do # Takes the index of $user and prints out seqentially $user & $pass

				printf "%s : %s\n\n" "${user[i]}" "${pass[i]}" >> SSH-Credentials.txt

				done

							

			fi

		fi

	done

	if [ "$(find ./ -type f -name "*-Credentials.txt" | wc -l)" -ge 1 ]; # Checks if the credentials files have one or more rows.
		then

		#clear
		printf "%bVulnerable Device/s On The Network, Please Seek Advice.\n\n" "$NCB"

		else
			printf	"\n"
			printf '%bAll Devices Seem Secure\n\n' "$NCB"
	fi

	rm -f {ips,lips,pass,user}.txt
	rm -f ./*.xml
	exit 1
		
		;;
		"Verbose Scan" )		

	echo
	rm -f SSH-Credentials.txt
	rm -f Telnet-Credentials.txt
	clear

	printf "%bScanning For Active Devices\n" "$GREEN"
	printf "%b\n" "$NC"

	ip a | grep -w "inet" | tail +2 | awk '{print $2}' > ips.txt # This gets the IP along with the subnet and is put into ips.txt for use with nmap.

	nmap -oG lips.txt -sP -iL ips.txt > /dev/null                # Nmap then scans for active IP addresses and saves them into l(ive)ips.txt.

	grep Host lips.txt | awk '{print $2}' > temp.txt; mv temp.txt lips.txt #Extracting the IP addresses and saving them.

	ips="$(wc lips.txt | awk '{print $1}')"
	printf "%bFound $ips live device/s on the network\n" "$NCB"
	printf "%b\n" "$NC"

	printf "%bScanning For Open Telnet Ports\n" "$GREEN"
	printf "%b\n" "$NC"
	    
	touch user.txt; echo admin >> user.txt; echo root >> user.txt; echo ubnt >> user.txt; echo support >> user.txt; echo service >> user.txt; echo guest >> user.txt; echo root >> user.txt
	touch pass.txt; echo admin >> pass.txt; echo root >> pass.txt; echo password >> pass.txt; echo guest >> pass.txt; echo service >> pass.txt; echo guest >> pass.txt; echo toor >> pass.txt

	open=$(nmap -iL lips.txt -p 23 | grep -E 'open' | awk '{print $2}' | wc | awk '{print $1}')

		printf "%bFound $open device/s with port 23 open\n\n" "$NCB"

	ips=$(cat 'lips.txt')


	for ip in $ips;  do

	test=$(nmap "$ip" -p 23 | grep -E 'open|closed' | awk '{print $2}')


		if [[ $test = 'open' ]]; then	

			printf "%bAttempting Dictionary Attack On $ip\n" "$RED"
			printf "%b\n" "$NC"

									
				var=$(nmap -oX Telnet-Credentials.xml -p 23 --script telnet-brute --script-args userdb=user.txt,passdb=pass.txt,telnet-brute.timeout=8s "$ip" | grep -E 'Valid' | awk '{print $4}')

				user=($(grep -o -P '(?<=username">).*(?=</elem>)' Telnet-Credentials.xml))
				pass=($(grep -o -P '(?<=password">).*(?=</elem>)' Telnet-Credentials.xml))	

			if [[ $var = *Valid* ]]; then

				echo "The telnet credentials for $ip are:" >> Telnet-Credentials.txt

				for i in "${!user[@]}"; do

				printf "%s : %s\n\n" "${user[i]}" "${pass[i]}" >> Telnet-Credentials.txt

			

				if [[ "$i" -lt 1 ]]; then

				
				printf "%bCredentials Found!\n\n" "$NCB"
				printf "%b" "$NC"

				fi

				printf "Log into the telnet server by running ${YELLOW}telnet -l ${user[i]} $ip${NC}\n\nWhen prompted enter the password found ${YELLOW}'${pass[i]}'\n"
				printf "%b\n" "$NC"

				done

				else printf "%bCredentials not found!\n\n%b" "$NCB" "$NC"		

			fi

		fi

done


	printf "%bScanning For Open SSH Ports\n" "$GREEN"
	printf "%b\n" "$NC"
	    

	open=$(nmap -iL lips.txt -p 22 | grep -E 'open' | awk '{print $2}' | wc | awk '{print $1}')

		printf "%bFound $open device/s with port 22 open\n\n" "$NCB"


	for ip in $ips;  do

	test=$(nmap "$ip" -p 22 | grep -E 'open|closed' | awk '{print $2}')


		if [[ $test = 'open' ]]; then	

		
			printf "%bAttempting Dictionary Attack On $ip\n" "$RED"
			printf "%b\n" "$NC"

									
				var=$(nmap -oX SSH-Credentials.xml -p 22 --script ssh-brute --script-args userdb=user.txt,passdb=pass.txt,telnet-brute.timeout=8s "$ip" | grep -E 'Valid' | awk '{print $4}')

				user=($(grep -o -P '(?<=username">).*(?=</elem>)' SSH-Credentials.xml))
				pass=($(grep -o -P '(?<=password">).*(?=</elem>)' SSH-Credentials.xml))

				if [[ $var = *Valid* ]]; then
						
					echo "The SSH credentials for $ip are:" >> SSH-Credentials.txt

				for i in "${!user[@]}"; do

				printf "%s : %s\n\n" "${user[i]}" "${pass[i]}" >> SSH-Credentials.txt

				if [[ "$i" -lt 1 ]]; then

				
				printf "%bCredentials Found!\n\n" "$NCB"
				printf "%b" "$NC"
				
				fi

				printf "Log into the SSH server by running %bssh %s@%s%b\n\nWhen prompted enter the password found %b'%s'\n" "$YELLOW" "${user[i]}" "$ip" "$NC" "$YELLOW" "${pass[i]}"
				printf "%b\n" "$NC"

				done

				else printf "%bCredentials not found!\n%b" "$NCB" "$NC"			

			fi

		fi

	done


	rm -f {ips,lips,pass,user}.txt
	rm -f ./*.xml


	exit 1
		;;

		"Quit" )
			exit 1
			;;


		*) printf "\n"
		   printf "%b'$REPLY' is not a valid option\n" "$RED"
		   printf "%b\n" "$NC"
	    ;;


					esac
				done

		
	    ;;

        "Previous Scan Results")

			if [ "$(find ./ -type f -name "*-Credentials.txt" | wc -l )" -ge 1 ];
				then

				clear
	    		cat Telnet-Credentials.txt
				cat SSH-Credentials.txt

				else
					printf	"\n"
	    			printf "%bNo credentials have been found\n\n" "$RED"
			fi
			break
            ;;

        "Quit")
            break
            ;;


        *) printf "\n"
		   printf "%b'$REPLY' is not a valid option\n" "$RED"
		   printf "%b\n" "$NC"
	    ;;

    esac
done