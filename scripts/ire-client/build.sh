#!/bin/bash

CONTAINER_NAME="ire-client"
CONTAINER_PATH="./decision-making-engine/client/"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

info_message "Stopping and removing $CONTAINER_NAME"
sudo docker stop $CONTAINER_NAME
sudo docker rm $CONTAINER_NAME
echo ""

info_message "Building $CONTAINER_NAME"
sudo docker build --tag $CONTAINER_NAME $CONTAINER_PATH
echo ""
