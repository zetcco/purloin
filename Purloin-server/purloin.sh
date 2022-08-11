#!/bin/bash

purloin_red="\033[1;31m"
purloin_green="\033[1;32m"
purloin_yellow="\033[1;33m"
purloin_blue="\033[1;34m"
purloin_purple="\033[1;35m"
purloin_cyan="\033[1;36m"
purloin_grey="\033[0;37m"
purloin_reset="\033[m"

cd ~/storage/shared/purloin
operation=
mode_silent=false
mode_test=false
mode_continuos=
mode_write=

out() {
	if [[ $1 = "info" ]]; then
		echo -e "${purloin_green}[*] $2${purloin_reset}"
	elif [[ $1 = "warn" ]]; then
		echo -e "${purloin_yellow}[!] $2${purloin_reset}"
	elif [[ $1 = "error" ]]; then
		echo -e "${purloin_red}[x] $2${purloin_reset}"
	fi
}

usage() { 
	echo -e -n "${purloin_red}"
	echo "Usage: $0 [-o Operation name] [-s Silent Mode] [-c Continuos mode] [-q Quick run] [-t Test run]" 1>&2
	echo -e "\tExample : Run with display output, with operation name as \"Operation_Name\"" 1>&2
	echo -e "\t\t $0 -o Operation_Name" 1>&2
	echo -e "\tExample : Quick Run in silent mode, continuosly" 1>&2
	echo -e "\t\t $0 -qcs" 1>&2
	echo -e "\tExample : Test run. Do not write to file." 1>&2
	echo -e "\t\t $0 -ct" 1>&2
	echo -e -n "${purloin_reset}"
	exit 1
}

create_op() {
	# If operation name is not specified
	if [ -d "./$1" ]; then
		if [[ $1 = "quick" ]]; then
			# echo -e "${yellow}[*] Running in quick operation mode.${reset}"
			out "warn" "Running in quick operation mode."
		else
	    	out "info" "Operation directory exists. Using existing."
	    fi
	else
	    out "info" "New Operation initiated."
	    mkdir ./$1
	fi
	operation=$1
}

while getopts tcqsho: name
do
	case $name in
		s)	# silent_mode
			mode_silent=true;;
		o)	# operaion creation
			create_op ${OPTARG};;
		c)	# continuos mode
			mode_continuos="-k"
			out "warn" "Running in continuos mode";;
		h)	# help
			usage;;
		q)	# quick run
			create_op "quick";;
		t)	# test mode (no write)
			mode_test=true;;
		?)	
			usage
			exit 2;;
		esac
done
shift $(($OPTIND - 1))

if [[ ! $OPTIND = 1 ]]; then
	if [[ $mode_test = true ]]; then
		out "warn" "Running in test mode. Writing to a file disabled."
		mode_write=""
	elif [[ ! -z $operation ]]; then
		mode_write="|& tee ./$operation/$(echo $operation)_$(date +%F_%I-%M-%p).purloin"

		if [[ $mode_silent = true ]]; then
			out "warn" "Running in silent mode."
			mode_write="&> ./$operation/$(echo $operation)_$(date +%F_%I-%M-%p).purloin"
		fi
	else
		usage
	fi

	# Set the IP of the domain "purloin.sytes.net" using No-Ip HTTP request
	server_ip=$(curl ifconfig.me) # Get the current public ip
	update_url="http://dynupdate.no-ip.com/nic/update?hostname=purloin.sytes.net&myip=${server_ip}"
	eval curl -u kranietisme@gmail.com:mrrobot@bin ${update_url} # Set the server ip
	eval ncat -l 25565 -v ${mode_continuos} ${mode_write} ${background_run}
else
	usage
fi
