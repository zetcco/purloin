#!/bin/bash

red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
blue="\033[1;34m"
purple="\033[1;35m"
cyan="\033[1;36m"
grey="\033[0;37m"
reset="\033[m"

cd ~/storage/shared/purloin
continuos=
write=
operation=
silent=false
test=false

out() {
	if [[ $1 = "info" ]]; then
		echo -e "${green}[*] $2${reset}"
	elif [[ $1 = "warn" ]]; then
		echo -e "${yellow}[!] $2${reset}"
	elif [[ $1 = "error" ]]; then
		echo -e "${red}[x] $2${reset}"
	fi
}

usage() { 
	echo -e -n "${red}"
	echo "Usage: $0 [-o Operation name] [-s Silent Mode] [-c Continuos mode] [-q Quick run] [-t Test run]" 1>&2
	echo -e "\tExample : Run with display output, with operation name as \"Operation_Name\"" 1>&2
	echo -e "\t\t $0 -o Operation_Name" 1>&2
	echo -e "\tExample : Quick Run in silent mode, continuosly" 1>&2
	echo -e "\t\t $0 -qcs" 1>&2
	echo -e "\tExample : Test run. Do not write to file." 1>&2
	echo -e "\t\t $0 -ct" 1>&2
	echo -e -n "${reset}"
	exit 1
}

create_op() {
	# If operation name is not specified
	if [ -d "./$1" ]; then
		if [[ $1 = "quick" ]]; then
			echo -e "${yellow}[*] Running in quick operation mode.${reset}"
		else
	    	echo -e "${green}[*] Operation directory exists. Using existing.${reset}"
	    fi
	else
	    echo -e "${green}[*] New Operation initiated.${reset}"
	    mkdir ./$1
	fi
	operation=$1
}

while getopts tcqsho: name
do
	case $name in
		s)	# silent_mode
			silent=true;;
		o)	# operaion creation
			create_op ${OPTARG};;
		c)	# continuos mode
			continuos="-k"
			out "warn" "Running in continuos mode";;
		h)	# help
			usage;;
		q)	# quick run
			create_op "quick";;
		t)	# test mode (no write)
			test=true;;
		?)	
			usage
			exit 2;;
		esac
done
shift $(($OPTIND - 1))

if [[ ! $OPTIND = 1 ]]; then
	if [[ $test = true ]]; then
		out "warn" "Running in test mode. Writing to a file disabled."
		write=""
	elif [[ ! -z $operation ]]; then
		write="|& tee ./$operation/$(echo $operation)_$(date +%F_%I-%M-%p).purloin"

		if [[ $silent = true ]]; then
			out "warn" "Running in silent mode."
			write="&> ./$operation/$(echo $operation)_$(date +%F_%I-%M-%p).purloin"
		fi
	else
		usage
	fi

	# echo "ncat -l 25565 -v ${continuos} ${write}"
	eval ncat -l 25565 -v ${continuos} ${write}
else
	usage
fi