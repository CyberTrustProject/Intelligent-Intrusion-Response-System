#!/bin/bash

CONTAINER_NAME="ire-server"
LOGFILE_PATH="/app/iirs/ire.log"
LOGFILE_NAME="ire.log"
GRAPH_PATH="/app/iirs/tmp/attack_graph_received.json"
GRAPH_NAME="attack_graph_received.json"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

info_message "Copying the logfile from $CONTAINER_NAME"
sudo docker cp $CONTAINER_NAME:$LOGFILE_PATH ./$LOGFILE_NAME
sudo chown $USER ./$LOGFILE_NAME
info_message "Copying the graph from $CONTAINER_NAME"
sudo docker cp $CONTAINER_NAME:$GRAPH_PATH ./$GRAPH_NAME
sudo chown $USER ./$GRAPH_NAME

mkdir ./ire-logs
mv ./$GRAPH_NAME ./$LOGFILE_NAME ./ire-logs
tar -czvf ire-logs.tar.gz ./ire-logs

rm -r ./ire-logs
echo ""
