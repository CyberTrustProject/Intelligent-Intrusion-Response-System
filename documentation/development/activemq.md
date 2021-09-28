# Download and extract the ActiveMQ Linux binaries.

```
mkdir activemq
cd activemq
wget -O "activemq.tar.gz" "http://www.apache.org/dyn/closer.cgi?filename=/activemq/5.15.12/apache-activemq-5.15.12-bin.tar.gz&action=download"
tar zxvf activemq.tar.gz
cd apache-activemq-5.15.12
```

# Setup ActiveMQ to have a single superuser (for debugging only).

Make the following changes to `./apache-activemq-5.15.12/config/activemq.xml`:
Add the following XML tags at the end of the `<broker>` tag. This will give the admin/admin user all rights to the topics (in production ADITESS shall ensure the correct rights).
```xml
<plugins>
    <simpleAuthenticationPlugin anonymousAccessAllowed="true">
        <users>
            <authenticationUser username="admin" password="admin" groups="users,admins,consumers,producers"/>
        </users>
    </simpleAuthenticationPlugin>
    <authorizationPlugin>
         <map>
             <authorizationMap>
                 <authorizationEntries>
                     <authorizationEntry queue=">" write="producers" read="consumers" admin="admins" />
                     <authorizationEntry topic=">" write="producers" read="consumers" admin="admins" />
                 </authorizationEntries>
             </authorizationMap>
         </map>
     </authorizationPlugin>
</plugins>
```

Make the following changes to `./apache-activemq-5.15.12/config/credentials.properties`:
```
activemq.username=admin
activemq.password=admin
guest.password=password
```

# Setup the iRG Server to connect to the local bus.

Set the correct URI to `attack-graph-engine/server/container/config.properties`:
The IP address will be the address assigned to the host system by Docker.
(The commented line works for my system, kpgram).
```
bus-uri=tcp://172.17.0.1:61616?jms.userName=admin&jms.password=admin
```

# Execute ActiveMQ.

Execute the ActiveMQ binary with `./bin/activemq console`
Connect to http://127.0.0.1:8161/admin/ to access the dashboard and create the `SOHO.Config` topic.
```
Username: admin
Password: admin
```

# Trigger the iRG Server bus subscription routine.

Initalize the iRG Server to subscribe to the `SOHO.Config` topic.
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/initialize

# Send the payload for call \#6 (POST:/topology/config)
```
{"header": {"source": "SMART_DEVICE_MODULE_ID","msg_topic": "SOHO.Config","timestamp": 1586142231,"msg_id": "dc542088-d3a7-4cb9-9420-88d3a75cb9ac","cor_id": ""},"payload": {"irg": {"hosts": [{"name": "pfsense","impact": "Negligeable"},{"id": "10000000-0000-0000-0000-000000000001","name": "host-000C292272F2","impact": "Negligeable"},{"id": "20000000-0000-0000-0000-000000000002","name": "host-000c29c5f1ce","impact": "Negligeable"}],"cost": {"patch": 3,"firewall": 1}},"ire": {"auto_mode": 0,"sa_tradeoff": 0.5,"sp_tradeoff": 3}}}
```

Example iRG Server log response:
```
INFO: [*] SOHO.Config Thread created to subscribe to the bus.
Apr 24, 2020 7:30:05 PM org.fiware.cybercaptor.server.rest.RestApplication print_message
INFO: [*] SOHO.Config Thread finished, stopped listening.

Apr 24, 2020 7:30:20 PM org.fiware.cybercaptor.server.rest.RestApplication print_message
INFO: [*] POST_topology_config recv: {"header": {"source": "SMART_DEVICE_MODULE_ID","msg_topic": "SOHO.Config","timestamp": 1586142231,"msg_id": "dc542088-d3a7-4cb9-9420-88d3a75cb9ac","cor_id": ""},"payload": {"irg": {"hosts": [{"name": "pfsense","impact": "Negligeable"},{"id": "10000000-0000-0000-0000-000000000001","name": "host-000C292272F2","impact": "Negligeable"},{"id": "20000000-0000-0000-0000-000000000002","name": "host-000c29c5f1ce","impact": "Negligeable"}],"cost": {"patch": 3,"firewall": 1}},"ire": {"auto_mode": 0,"sa_tradeoff": 0.5,"sp_tradeoff": 3}}}
Apr 24, 2020 7:30:20 PM org.fiware.cybercaptor.server.rest.RestApplication print_message
INFO: [*] Payload sent: 200
Apr 24, 2020 7:30:20 PM org.fiware.cybercaptor.server.rest.RestApplication print_message
INFO: [*] POST_topology_config answ: {"payload":{"result":{"message":"Hosts configuration was successfully loaded.","status":"OK","code":200},"api":"3.1.0"},"header":{"timestamp":1587756620,"msg_topic":"SOHO.Config","cor_id":"dc542088-d3a7-4cb9-9420-88d3a75cb9ac","source":"00000000-0000-0000-0000-000000000000","msg_id":"f778e285-bfb2-44bd-b8e2-85bfb204bde6"}}
```
