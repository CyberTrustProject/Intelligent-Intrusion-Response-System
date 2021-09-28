#!/bin/bash

CONTAINER_NAME="ag-engine-server"

function info_message () {
    echo -e "\e[95m[*] $1\e[0m"
}

sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/net-ip.json ./net-ip.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/vuln-scan-report.json ./vuln-scan-report.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/hosts-interfaces.json ./hosts-interfaces.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/vlans.json ./vlans.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/flow-matrix.json ./flow-matrix.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/routing.json ./routing.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/MulVAL.json ./MulVAL.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/Reduced-1.json ./Reduced-1.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/Reduced-2.json ./Reduced-2.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/Final.json ./Final.json
sudo docker cp $CONTAINER_NAME:/root/.remediation/logs/iRE.json ./iRE.json
sudo chown $USER ./*.json

sudo docker cp $CONTAINER_NAME:/root/.remediation/inputs/topology-generated.xml ./topology-generated.xml
sudo chown $USER ./topology-generated.xml

mkdir ./irg-logs
mv ./*.json ./topology-generated.xml ./irg-logs
tar -czvf irg-logs.tar.gz ./irg-logs

rm -r ./irg-logs
echo ""
