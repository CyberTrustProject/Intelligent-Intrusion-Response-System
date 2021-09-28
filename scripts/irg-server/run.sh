#!/bin/bash

CONTAINER_NAME="ag-engine-server"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

info_message "Stopping and removing $CONTAINER_NAME"
sudo docker stop $CONTAINER_NAME
sudo docker rm $CONTAINER_NAME
echo ""

info_message "Starting $CONTAINER_NAME"
sudo docker run -d --name $CONTAINER_NAME -p 10000:8080 $CONTAINER_NAME
echo ""
