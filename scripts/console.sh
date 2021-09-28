#!/bin/bash

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

function warning_message () {
    echo -e "\e[95m[!] $1\e[0m"
}

if [ -z "$1" ]
then
    warning_message "A docker container name is required."
else
    sudo docker exec -it $1 bash
fi
