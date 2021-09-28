#!/bin/bash

IP="127.0.0.1"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

function warning_message () {
    echo -e "\e[95m[!] $1\e[0m"
}

if [ -z "$1" ]
then
    warning_message "A filename is required."
else
    info_message "Initializing the iRE Server using: $1"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:17891/topology < $1
    echo ""
fi
