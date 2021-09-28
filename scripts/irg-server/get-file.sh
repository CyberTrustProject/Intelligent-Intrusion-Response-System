#!/bin/bash

CONTAINER_NAME="ag-engine-server"
FILE_RIGHTS=644 # rw-rw-r--

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
    info_message "Copying $1 from $CONTAINER_NAME"
    sudo docker cp $CONTAINER_NAME:/root/.remediation/$1 ./$1
    sudo chown $USER ./$1
    chmod $FILE_RIGHTS ./$1
    echo ""
fi
