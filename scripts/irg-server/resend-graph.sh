#!/bin/bash

CONTAINER_NAME="ag-engine-server"
GRAPH_FILE="/root/.remediation/logs/iRE.json"
IRE_IP="172.17.0.1"

function warning_message () {
    echo -e "\e[95m[!] $1\e[0m"
}

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

info_message "Resending the graph to the iRE."
sudo docker exec -it $CONTAINER_NAME curl -v -X POST -H "Content-Type: application/json" --data "@$GRAPH_FILE" http://$IRE_IP:17891/topology