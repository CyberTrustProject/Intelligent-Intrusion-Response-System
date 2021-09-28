#!/bin/bash

IP="127.0.0.1"
CONTAINER_NAME="ag-engine-server"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

function warning_message () {
    echo -e "\e[95m[!] $1\e[0m"
}

echo -e "\nThis program initializes the iRG server with a directory's JSON files."
echo -e "Usage: $0 [path to directory]\n"

if [ -z "$1" ]
then
    warning_message "A folder path is required."
else
    cd $1

    info_message "Calling: /topology/net-ip"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/net-ip < ./net-ip.json
    echo -e "\n"

    info_message "Calling: /topology/vuln-scan-report"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/vuln-scan-report < ./vuln-scan-report.json
    echo -e "\n"

    info_message "Calling: /topology/hosts-interfaces"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/hosts-interfaces < ./hosts-interfaces.json
    echo -e "\n"

    info_message "Calling: /topology/vlans"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/vlans < ./vlans.json
    echo -e "\n"

    info_message "Calling: /topology/flow-matrix"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/flow-matrix < ./flow-matrix.json
    echo -e "\n"

    info_message "Calling: /topology/routing"
    curl -X POST -H "Content-Type: application/json" -d @- http://$IP:10000/ag-engine-server/rest/json/v2/topology/routing < ./routing.json
    echo -e "\n"

    info_message "Initializing the system."
    curl http://$IP:10000/ag-engine-server/rest/json/v2/initialize
    echo -e "\n"
fi
