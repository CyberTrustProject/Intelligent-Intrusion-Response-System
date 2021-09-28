#!/bin/bash

CONTAINER_NAME="ag-engine-client"
CONTAINER_PATH="./attack-graph-generator/client/container/"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

info_message "Stopping and removing $CONTAINER_NAME"
sudo docker stop $CONTAINER_NAME
sudo docker rm $CONTAINER_NAME
echo ""

info_message "Building $CONTAINER_NAME"
sudo docker build --build-arg CACHE_DATE="$(date)" --build-arg SSH_PRIVATE_KEY="$(cat ~/.ssh/id_rsa)" --build-arg GIT_BRANCH="$(git symbolic-ref --short HEAD)" --tag $CONTAINER_NAME $CONTAINER_PATH
echo ""
