# iIRS Decision-Making Engine RestAPI Call Reference

**Version 1: 01/Nov/2019**

**Changelog**

| Date        | Description |
| ----------- | ----------- |
| 01/Nov/2019 | Document creation. |

## List of Endpoints

**The API of the Decision-Making Engine Server is available at:**\
`http://127.0.0.1:17891/`


**Status field explanation:**\
:heavy_check_mark: = Completed\
:heavy_minus_sign: = In Development / Unfinished

| #  | Request Method | Endpoint | Description | Status |
| :-: | -------------: | -------- | ----------- | :----: |
| 1  | GET  | /parameters | Get current parameter values. | :heavy_minus_sign: |
| 2  | POST  | /parameters | Set parameter values | :heavy_check_mark: |
| 3  | POST  | /uploadTopology | Send the topology of the attack graph and initiate decision making engine | :heavy_check_mark: |
| 4  | GET  | /getDecision | Get the last decision made by the engine | :heavy_minus_sign: |
| 5  | GET  | /getBelief | Get the current belief of the system state | :heavy_minus_sign: |
| 6  | ??  | ?? | Communication with IDS | :heavy_minus_sign: |
| 7  | ??  | ?? | Action Retrieval | :heavy_minus_sign: |

## Data Message Examples


### 1 - Parameter message - json format.
**POST:** `http://127.0.0.1:17891/parameters`

**Response:**
200

**Request Data:**
<details>
<summary>Click to collapse/fold.</summary>

```json
    {
      'min_iterations' : 2000,
      'no_particles': 1200,
      'security_availability_tradeoff' : 0.5,
      'max_processes' : 16
    }
```

</details>


### 2 - Parameter message - json format.
**GET:** `http://127.0.0.1:17891/parameters`

**Response:**
<details>
<summary>Click to collapse/fold.</summary>

```json
    {
      'min_iterations' : 2000,
      'no_particles': 1200,
      'security_availability_tradeoff' : 0.5,
      'max_processes' : 16
    }
```

</details>



### 3 - Network Topology message - json format.
**POST:** `http://127.0.0.1:17891/uploadTopology`

**Response:**
200

**Request Data:**
<details>
<summary>Click to collapse/fold.</summary>

```json
    {"attack_graph": {"arcs": {"arc": [{"dst": 3, "prob": 0, "src": 2}, {"dst": 2, "prob": 0, "src": 1}, {"dst": 6, "prob": 0, "src": 5}, {"dst": 5, "prob": 0, "src": 4}, {"dst": 15, "prob": 0, "src": 14}, {"dst": 14, "prob": 0, "src": 13}, {"dst": 13, "prob": 1, "src": 12}, {"dst": 18, "prob": 0, "src": 17}, {"dst": 19, "prob": 0, "src": 17}, {"dst": 20, "prob": 0, "src": 17}, {"dst": 17, "prob": 0, "src": 16}, {"dst": 16, "prob": 1, "src": 12}, {"dst": 12, "prob": 0, "src": 11}, {"dst": 11, "prob": 1, "src": 10}, {"dst": 21, "prob": 1, "src": 10}, {"dst": 22, "prob": 1, "src": 10}, {"dst": 23, "prob": 1, "src": 10}, {"dst": 1, "prob": 1, "src": 10}, {"dst": 10, "prob": 0, "src": 9}, {"dst": 9, "prob": 1, "src": 8}, {"dst": 24, "prob": 1, "src": 8}, {"dst": 22, "prob": 1, "src": 8}, {"dst": 25, "prob": 1, "src": 8}, {"dst": 8, "prob": 0, "src": 7}]}, "vertices": {"vertex": [{"fact": "execCode('linux-user-1',root)", "id": 1, "init_risk": 0, "metric": 0, "related_host": {"hostname": "linux-user-1"}, "type": "OR"}, {"fact": "RULE 3 (Attacker is root on his machine)", "id": 2, "init_risk": 0, "metric": 0, "type": "AND"}, {"fact": "attackerLocated('linux-user-1')", "id": 3, "init_risk": 1, "metric": 1, "related_host": {"hostname": "linux-user-1"}, "type": "LEAF"}, {"fact": "execCode('linux-user-2',root)", "id": 4, "init_risk": 0, "metric": 0, "related_host": {"hostname": "linux-user-2"}, "type": "OR"}, {"fact": "RULE 3 (Attacker is root on his machine)", "id": 5, "init_risk": 0, "metric": 0, "type": "AND"}, {"fact": "attackerLocated('linux-user-2')", "id": 6, "init_risk": 1, "metric": 1, "related_host": {"hostname": "linux-user-2"}, "type": "LEAF"}, {"fact": "execCode('linux-user-2',user)", "id": 7, "init_risk": 0, "metric": 0, "related_host": {"hostname": "linux-user-2"}, "type": "OR"}, {"fact": "RULE 1 (remote exploit of a server program)", "id": 8, "init_risk": 1, "metric": 0, "type": "AND"}, {"fact": "netAccess('192.168.1.112','TCP',5353)", "id": 9, "init_risk": 0, "metric": 0, "related_host": {"hostname": "linux-user-2"}, "type": "OR"}, {"fact": "RULE 2 (multi-hop access)", "id": 10, "init_risk": 1, "metric": 0, "type": "AND"}, {"fact": "hacl('192.168.1.111','192.168.1.112','TCP',5353)", "id": 11, "init_risk": 0, "metric": 0, "related_host": {"hostname": "linux-user-2"}, "type": "OR"}, {"fact": "RULE 8 (Access enabled between hosts in same vlan)", "id": 12, "init_risk": 1, "metric": 0, "type": "AND"}, {"fact": "localAccessEnabled('192.168.1.111','192.168.1.112',port)", "id": 13, "init_risk": 0, "metric": 0, "type": "OR"}, {"fact": "RULE 12 (No local filtering on this host)", "id": 14, "init_risk": 0, "metric": 0, "type": "AND"}, {"fact": "defaultLocalFilteringBehavior('192.168.1.112',allow)", "id": 15, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "RULE 7 (Interfaces are in the same vlan)", "id": 17, "init_risk": 0, "metric": 0, "type": "AND"}, {"fact": "ipInSameVLAN('192.168.1.111','192.168.1.112')", "id": 16, "init_risk": 0, "metric": 0, "type": "OR"}, {"fact": "\\==('192.168.1.111','192.168.1.112')", "id": 19, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "isInVlan('192.168.1.112','user-lan')", "id": 18, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "\\==('linux-user-1','linux-user-2')", "id": 21, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "isInVlan('192.168.1.111','user-lan')", "id": 20, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "hasIP('linux-user-1','192.168.1.111')", "id": 23, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "hasIP('linux-user-2','192.168.1.112')", "id": 22, "init_risk": 1, "metric": 1, "type": "LEAF"}, {"fact": "vulExists('linux-user-2','CVE-2007-2446',mdns,remoteExploit,privEscalation)", "id": 25, "init_risk": 1, "metric": 1, "related_host": {"cpe": "cpe:/", "hostname": "linux-user-2", "ip": "192.168.1.112", "port": 5353, "protocol": "TCP", "service": "mdns"}, "type": "LEAF"}, {"fact": "networkServiceInfo('192.168.1.112',mdns,'TCP',5353,user)", "id": 24, "init_risk": 1, "metric": 1, "related_host": {"cpe": "cpe:/", "hostname": "linux-user-2", "ip": "192.168.1.112", "port": 5353, "protocol": "TCP", "service": "mdns"}, "type": "LEAF"}]}}}
```

</details>





### 4 - Decision message - json format.
**GET:** `http://127.0.0.1:17891/getDecision`

**Response:**
In development




### 4 - Belief message - json format.
**GET:** `http://127.0.0.1:17891/getBelief`

**Response:**
In development

## To Build:

### iIRS - Server
1. To build the docker image:
    ```bash
    cd ./iIRS/iIRS_server/
    sudo docker build --tag=iirsserver iIRS_server
    ```
2. To run the docker image on `127.0.0.1:10000`:
    ```bash
    sudo docker run --network host iirsserver
    ```

### iIRS - Client
1. To build the docker image:
    ```bash
    cd ./iIRS/iIRS_client/
    sudo docker build --tag=iirsclient iIRS_client
    ```
2. To run the docker image on `127.0.0.1:10000`:
    ```bash
    sudo docker run -p 4200:4200 iirsclient
    ```