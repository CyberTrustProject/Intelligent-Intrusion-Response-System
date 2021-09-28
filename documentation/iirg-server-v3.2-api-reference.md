# iIRS Attack Graph Generator (iRG) Server RestAPI Call Reference

**Version 3.2.2: 24/Sep/2020**

**Table of Contents:**

1. [List of Endpoints](#list-of-endpoints)
2. [Session Management](#session-management)
3. [JSON Structure](#json-structure)
4. [Java JSON Structure Creation API](#java-v2-json-structure-creation-api)
    * [Function Signatures](#function-signatures-and-enumerations)
    * [Usage Examples](#usage-examples)
    * [Payload Signing Process](#payload-signing-process)
5. [Data Message Examples](#data-message-examples)
6. [Changelog](#changelog)

## List of Endpoints

**The API of the Attack Graph Engine Server is available at:**\
`http://127.0.0.1:10000/ag-engine-server/rest/json/v2`

*Note: the endpoint is still `ag-engine-server/rest/json/v2` regardless of the actual API version, to avoid service disruption by renaming it.*

| #   | Request Method | Endpoint | Description | Bus Topic |
| :-: | -------------: | -------- | ----------- | --------- |
| 1   | GET  | [/system/test](#1-test-call-that-tests-and-generates-a-generic-response) | Test call that tests and generates a generic response. |  |
| 2   | GET  | [/system/info](#2-information-about-the-irg-instance) | Information about the iRG instance. |  |
| 3   | GET  | /system/database/update | Updates the remediation DB with new entries that can be found on MISP regarding the current date. |  |
| 4   | GET  | [/topology](#4-get-the-providedgenerated-topology-in-xml-form) | Get the provided/generated topology in XML form. | Network.Topology |
| 5   | GET  | [/topology/config](#5-get-the-list-of-hosts-and-their-security-requirements) | Get the list of hosts and their security requirements. | SOHO.Config |
| 6   | POST | [/topology/config](#6-set-the-list-of-hosts-and-their-security-requirements) | Set the list of hosts and their security requirements. | SOHO.Config |
| 7   | POST | [/topology/net-ip](#7-set-the-networks-in-cidr-format-to-be-considered-when-constructing-the-network-topology) | Set the networks (in CIDR format) to be considered when constructing the network topology. |  |
| 8   | POST | [/topology/vuln-scan-report](#8-upload-the-vulnerability-scan-report-results) | Upload the vulnerability scan report results. |  |
| 9   | POST | [/topology/hosts-interfaces](#9-upload-the-host-list-incl-network-interface-information) | Upload the host list, incl. network interface information. |  |
| 10  | POST | [/topology/vlans](#10-upload-the-vlans-list) | Upload the vlans list. |  |
| 11  | POST | [/topology/flow-matrix](#11-upload-the-network-flow-matrix) | Upload the network flow matrix. |  |
| 12  | POST | [/topology/routing](#12-upload-the-routing-tables) | Upload the routing tables. |  |
| 13  | GET  | [/initialize](#13-system-initialization-generates-the-attack-graph-with-on-disk-data) | System initialization. Generates the attack graph with on-disk data. |  |
| 14  | POST | [/initialize](#14-system-initialization-generates-the-attack-graph-with-the-provided-xml-topology) | System initialization. Generates the attack graph with the provided XML topology. |  |
| 15  | GET  | [/attack-graph](#15-get-the-mulval-generated-attack-graph) | Get the MulVAL-generated attack graph. |  |
| 16  | GET  | [/attack-graph/risk](#16-get-risk-ratings-for-each-network-host) | Get risk ratings for each network host. | Network.Risk |
| 17  | GET  | [/attack-graph/topological](#17-get-the-topological-form-of-the-attack-graph) | Get the topological form of the attack graph. |  |
|     | GET  | /attack-graph/reduced | Get the reduced form of the MulVAL-generated attack graph. |  |
| 18  | GET  | [/attack-graph/remediations](#18-get-all-actionable-remediations-for-the-whole-attack-graph) | Get all actionable remediations for the whole attack graph. |  |
| 19  | POST | [/attack-graph/remediations/block-nodes](#19-generate-firewall-rules-to-block-a-specific-attack-graph-node) | Generate firewall rules to block a specific attack graph node. |  |
| 20  | GET  | [/attack-path/list](#20-get-all-attack-paths) | Get all attack paths. |  |
| 21  | GET  | [/attack-path/number](#21-get-the-number-of-attack-paths) | Get the number of attack paths. | Applicable.Mitigations |
| 22  | GET  | [/attack-path/{id}](#22-get-the-specified-attack-path) | Get the specified attack path. |  |
| 23  | GET  | [/attack-path/{id}/topological](#23-get-the-topological-form-of-the-specified-attack-path) | Get the topological form of the specified attack path. |  |
| 24  | GET  | [/attack-path/{id}/remediations](#24-get-the-remediations-for-the-specified-attack-path) | Get the remediations for the specified attack path. | Applicable.Mitigations |
| 25  | GET  | [/attack-path/{id}/remediation/{id}](#25-simulate-the-specified-remediation-on-the-specified-attack-path-and-compute-the-new-attack-graph) | Simulate the specified remediation on the specified attack path and compute the new attack graph. |  |
| 26  | GET  | [/attack-path/{id}/remediation/{id}/validate](#26-validate-that-the-specified-remediation-has-been-applied) | Validate that the specified remediation has been applied. |  |

## Call Classes

Calls can be classified under the following four groups:
1. **System Calls (\#1, \#2 \& \#3)** - Calls concerning maintenance and testing functions which can be used at any time and by any cooperating module.
2. **Pre-initialization Calls (\#7-12)** - Calls concerning the storage and retrieval of input data.
3. **Initialization Calls (\#13 \& \#14)** - Calls which trigger the internal mechanism of iRG Server.
4. **Post-initialization Calls (\#4-6 \& \#15-26)** - Calls providing access to the results of the algorithms and processes triggered by the initialization calls. Plus, calls requiring access to data created during the initialization phase.

## JSON Structure
```json
{
    "header": {
        "source": "SMART_DEVICE_MODULE_ID",
        "msg_topic": "INFORMATION_BUS_TOPIC",
        "timestamp": UNIX_EPOCH_AT_GENERATION,
        "msg_id": "UUID_V4",
        "cor_id": "MSG_ID_OF_PREV_MESSAGE",
        "sign_alg": "ALGORITHM_NAME"
    },
    "payload": {
        "metadata": {
            "api": "IRG_SERVER_API_VERSION",
            "status": "SUCCESS_FAILURE_KEYWORD",
            "message": "MESSAGE_FOR_THE_USER"
        },
        "foo": "bar"
    },
    "trailer": {
        "signature": "BASE_64_ENCODED_SIGNATURE"
    }
}
```

| Field | Description | Type | Presence |
| ----: | ----------- | ---- | -------- |
| `header` | Information about the message. Included in the signing process. | **Object** | Mandatory |
| `payload` | The response of each call (as defined per call). Included in the signing process. | **Object** | Mandatory |
| `trailer` | Information about the message.<br>**Not included in the signing process.** | **Object** | Mandatory<br><br>*If any of its fields are present.* |
| `header/source` | The ID of the Smart Device Module the iRG Server is running on. | **String** | Mandatory |
| `header/msg_topic` |  Predefined keyword to identify the information bus topic. | **String**<br>See following enum.<br>E.g: "Device.Vulnerability" | Mandatory |
| `header/msg_id` | A universal identification number (UUID) uniquely identifying each message. | **String**<br>UUID v4<br>E.g: "dc2749ff-7722-4939-a749-ff77220939c2" | Mandatory |
| `header/cor_id` | Identifier grouping individual messages together (in the form of a conversation). An initial message will have an empty `cor_id`, otherwise if a message is a reply to an older message, then `cor_id` contains the `msg_id` of that message. | **String**<br>UUID | Optional |
| `header/timestamp` | The timestamp generated at response time in the UNIX epoch format. | **Number**<br>UNIX Epoch<br>E.g: 1572912541392 | Mandatory |
| `header/sign_alg` | The algorithm used to sign the payload. | **String**<br>HashAlgorithm + "With" + EncryptionAlgorithm<br>E.g: “sha256WithRSAEncryption” | Mandatory<br><br>*If contents are signed.* |
| `trailer/signature` | The actual signature of the payload, in Base64 encoding. | **String**<br>Base64-encoded signarure (see following explanation) | Mandatory<br><br>*If contents are signed.* |
| `payload/metadata/api` |  The version of the iRG Server API.<br>To track and detect if updates to the JSON structure (in the payload) were made. | **String**<br>"##.##.##" or "##.##.##b" (for beta versions)<br>E.g: "1.2.3" | Mandatory |
| `payload/metadata/status` | The status of the result.<br>Whether the operation was successful or failed. | **String**<br>"OK" or "ERROR" | Mandatory |
| `payload/metadata/message` | A message explaining the status of the call. | **String**<br>E.g: "The initialization procedure was successful." | Mandatory |

## Payload Signing Process

The payload signing process requires both the private key and the certificate in PEM format to be available at `./crypto-keys/`.

For example such pair can be generated by OpenSSL with the following command:
`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes`

<details>
<summary>Console logs for the creation of the keys used in this repository.</summary>

```
user@lubuntu-pc:~/Desktop$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes
Generating a RSA private key
....++++
.....................................................................................................................................++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:eu
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:City
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Company
Organizational Unit Name (eg, section) []:Name
Common Name (e.g. server FQDN or YOUR name) []:iirs1234
Email Address []:
```

</details>


The signature generation process for the following response example will be presented:
<details>
<summary>Raw response:</summary>

```json
{"trailer":{"signature":"CSjF89YX39+Q07yjlSgGrFXRui0cIGMHyWl5JIMxF7jhQI2coXTQPqCFdMOqz/h91gmRkH6lP3qVmx2QO9UlZz7lUnyuGcD0hw+rgGiQbcNCcjyqcgu6fX5gMKsYaKaq/sNO3OTURfwvCxBvddu4rzVJHpM8XiDZrSbL2g48VlxAquBg4BJlAaLJGMoq1E9qzeNm8C1mJjW5U/4FsFR00FZWqrCQaDp4B9w6g8XHVUVDOXsfK/zKQAcUJatrsAfc2KPGk+zr/J7pKndDBxG70ZYh70u8l41UyexDWnYwxQ5uBnp+roFFOLZpL6OJbcJzqOy8zpkYe5cP7ad5tAQE4rh7gMgmoSpmN78HDuS81H6p1GglT31WVRb7Q2bgTtV2fnL3ACAUWhOYQCyu0r4b8ldsdJM7E0QGvmgOJT8kOV29AhR5l8eBtGL+QgQycznS9Xc2gPCK/Ca+38jckzexmJlcrPmQ1+SgLLd3KSpgIG5Tab67hSYfTO4KVmAZdWRfZR8Vg10IXOKdFd1nT+ob047rMqi+x4ZK3C/RfTa4A8ADhjAoW16VnusWlu4LDXS4oG1wVywPTqe0tZrqekoYP7XWA7Om3dTLmghBTET810IG/RS1SMM/0yN3Dxj62oTrGLOirkLhdsjZMZKHjgkiZ13KyKY/7gp1qEj+vfSWEh4="},"payload":{"metadata":{"message":"iRG test response.","status":"OK","api":"3.2.1"}},"header":{"timestamp":1589281512,"msg_topic":"Internal.iRG.Test","source":"iirs1234.cybertrust.eu","sign_alg":"sha256WithRSAEncryption","msg_id":"93f08fb3-9e2d-4bfc-b08f-b39e2dbbfcdc"}}
```

</details>

<details>
<summary>Formatted response:</summary>

```json
{
    "trailer": {
        "signature": "CSjF89YX39+Q07yjlSgGrFXRui0cIGMHyWl5JIMxF7jhQI2coXTQPqCFdMOqz/h91gmRkH6lP3qVmx2QO9UlZz7lUnyuGcD0hw+rgGiQbcNCcjyqcgu6fX5gMKsYaKaq/sNO3OTURfwvCxBvddu4rzVJHpM8XiDZrSbL2g48VlxAquBg4BJlAaLJGMoq1E9qzeNm8C1mJjW5U/4FsFR00FZWqrCQaDp4B9w6g8XHVUVDOXsfK/zKQAcUJatrsAfc2KPGk+zr/J7pKndDBxG70ZYh70u8l41UyexDWnYwxQ5uBnp+roFFOLZpL6OJbcJzqOy8zpkYe5cP7ad5tAQE4rh7gMgmoSpmN78HDuS81H6p1GglT31WVRb7Q2bgTtV2fnL3ACAUWhOYQCyu0r4b8ldsdJM7E0QGvmgOJT8kOV29AhR5l8eBtGL+QgQycznS9Xc2gPCK/Ca+38jckzexmJlcrPmQ1+SgLLd3KSpgIG5Tab67hSYfTO4KVmAZdWRfZR8Vg10IXOKdFd1nT+ob047rMqi+x4ZK3C/RfTa4A8ADhjAoW16VnusWlu4LDXS4oG1wVywPTqe0tZrqekoYP7XWA7Om3dTLmghBTET810IG/RS1SMM/0yN3Dxj62oTrGLOirkLhdsjZMZKHjgkiZ13KyKY/7gp1qEj+vfSWEh4="
    },
    "payload": {
        "metadata": {
            "message": "iRG test response.",
            "status": "OK",
            "api": "3.2.1"
        }
    },
    "header": {
        "timestamp": 1589281512,
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "sign_alg": "sha256WithRSAEncryption",
        "msg_id": "93f08fb3-9e2d-4bfc-b08f-b39e2dbbfcdc"
    }
}
```

</details>

The process starts with this exact string representation of the combined contents of both `header` \& `payload` structures.

```json
{"payload":{"metadata":{"message":"iRG test response.","status":"OK","api":"3.2.1"}},"header":{"timestamp":1589281512,"msg_topic":"Internal.iRG.Test","source":"iirs1234.cybertrust.eu","sign_alg":"sha256WithRSAEncryption","msg_id":"93f08fb3-9e2d-4bfc-b08f-b39e2dbbfcdc"}}
```
Note the complete absence of whitespace (except of course from the contents of the string fields).

The final signature is the Base64 encoded results of the structure described in [PKCS \#1](http://www.rfc-editor.org/rfc/rfc2437.txt) (as detailed by the [Java Cryptography Architecture manual](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature)).
The only currently supported process is the `sha256WithRSAEncryption`.

A simple Java code sample of this process can be found in [java-crypto.md](documentation/development/java-crypto.md).

## Data Message Examples

### 1 - Test call that tests and generates a generic response
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/test`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/test
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "ffd44aa0-e2fb-4a9e-944a-a0e2fbfa9ed4",
        "msg_topic": "Internal.iRG.Test",
        "sign_alg": "sha256WithRSAEncryption",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588640185
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "iRG test response.",
            "status": "OK"
        }
    },
    "trailer": {
        "signature": "XOlF5QzqmyQybFGqrrHN2EyEMRjTUVO/Qkv1qwEftJD+O/Ts3HducQdCxWKPl/FDWp8WTTibb0M442fD5oNzB9lV5O20rH1cTJTmkSB0rKBlfc7DoaUpboG+JAi81NXIks0G5pqgq0/lWzsaD9z5ov73r22FvRsXl45Ranfn8loLWaEN5VslQSqZrIN+zd3Kw4lCBJvd7kDBgalpX3xKk8cUJrIuo0U3pvz+8YckKI2kY7f9NYwbnUBPtbJP2nMyOwM19Ho0jeY+lJFPixF1qFD3jJKRPH9tVjNGaAlNfXpih5JhfqTXYuFwStrof55j/Swp2uqM4ZJ9bfEGJA9MrzrpHWPfvoRM2Cx9u+mCM+hWTitOu6NEU1FNs68dMDfCV4ol/BIDB4c4ipMtyPSBBvhHoEZhxH1DWTkGbEZvztvvrqnR5uFCpFhDAHcP0RvLFIYXI9AYsyhnGc1HPsiYvwQYnpfWSP5Pqb/BeqsXX78x5CGYNQHuxMQfoi2GNXhI9TrAvsTy368ipbKTjmu6+b4TfLNRldBM+quKQBEtivi7tNWOazn3ToanOtX2MbhQ7OYWpZRR8Xi0A2ZHlppHh9nuv24KEzNK2aNPe9XrvMKO5EVt56c7nv52fNrJHNqgoFay6CPWv2a4jn0jPDISG+yKa6iSnmRIfEe66yesTRE="
    }
}
```

</details>

---

### 2 - Information about the iRG instance
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/info`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/info
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f982e208-697e-4f46-82e2-08697e2f463c",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588640217
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "iRG Server instance info successfully retrieved.",
            "status": "OK"
        },
        "initialized": {
            "state": false,
            "timestamp": 1588640217
        }
    }
}
```

</details>

---

### 3 -
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/database/update`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/system/database/update
```

<details>
<summary>Response:</summary>

```json

```

</details>

---

### 4 - Get the provided/generated topology in XML form
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "55295f50-37ac-4667-a95f-5037ac066798",
        "msg_topic": "Response.Topology",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588640523
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Topology XML generated.",
            "status": "OK"
        },
        "topology": "<topology><machine><name>pfsense</name><cpe>cpe:/</cpe><interfaces><interface><name>em0</name><vlan><name>VLAN00</name><label>VLAN00</label></vlan><ipaddress>10.0.10.1</ipaddress><directly-connected><ipaddress>10.0.10.110</ipaddress><ipaddress>10.0.10.105</ipaddress><internet /></directly-connected></interface></interfaces><services><service><name>dnsmasq domain</name><ipaddress>10.0.10.1</ipaddress><protocol>TCP</protocol><port>53</port><CPE>cpe:/</CPE></service><service><name>openssh ssh</name><ipaddress>10.0.10.1</ipaddress><protocol>TCP</protocol><port>22</port><CPE>cpe:/</CPE><vulnerabilities><vulnerability><type>remoteExploit</type><goal>privEscalation</goal><cve>CVE-2018-15919</cve></vulnerability><vulnerability><type>remoteExploit</type><goal>privEscalation</goal><cve>CVE-2017-15906</cve></vulnerability></vulnerabilities></service><service><name>nginx http</name><ipaddress>10.0.10.1</ipaddress><protocol>TCP</protocol><port>80</port><CPE>cpe:/</CPE></service></services><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>10.0.10.1</gateway><interface>em0</interface></route><route><destination>10.0.10.0</destination><mask>255.255.255.0</mask><gateway>10.0.10.1</gateway><interface>em0</interface></route></routes><input-firewall><default-policy>ACCEPT</default-policy></input-firewall><output-firewall><default-policy>ACCEPT</default-policy></output-firewall></machine><machine><name>host-000C292272F2</name><cpe>cpe:/</cpe><interfaces><interface><name>fa0</name><vlan><name>VLAN00</name><label>VLAN00</label></vlan><ipaddress>10.0.10.110</ipaddress><directly-connected><ipaddress>10.0.10.1</ipaddress><ipaddress>10.0.10.105</ipaddress><internet /></directly-connected></interface></interfaces><services /><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>10.0.10.1</gateway><interface>fa0</interface></route></routes><input-firewall><default-policy>ACCEPT</default-policy></input-firewall><output-firewall><default-policy>ACCEPT</default-policy></output-firewall></machine><machine><name>host-000c29c5f1ce</name><cpe>cpe:/</cpe><interfaces><interface><name>fa0</name><vlan><name>VLAN00</name><label>VLAN00</label></vlan><ipaddress>10.0.10.105</ipaddress><directly-connected><ipaddress>10.0.10.1</ipaddress><ipaddress>10.0.10.110</ipaddress><internet /></directly-connected></interface></interfaces><services><service><name>openssh ssh</name><ipaddress>10.0.10.105</ipaddress><protocol>TCP</protocol><port>22</port><CPE>cpe:/</CPE></service><service><name>wsgiserver/0.2 cpython/3.6.8 http-alt</name><ipaddress>10.0.10.105</ipaddress><protocol>TCP</protocol><port>8000</port><CPE>cpe:/</CPE></service></services><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>10.0.10.1</gateway><interface>fa0</interface></route></routes><input-firewall><default-policy>ACCEPT</default-policy></input-firewall><output-firewall><default-policy>ACCEPT</default-policy></output-firewall></machine></topology>"
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "8f476954-f459-4ffc-8769-54f4595ffce1",
        "msg_topic": "Response.Topology",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588640605
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 5 - Get the list of hosts and their security requirements
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/config`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/config
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "msg_id": "76acfea7-e223-4474-acfe-a7e223847475",
        "msg_topic": "SOHO.Config",
        "sign_alg": "sha256WithRSAEncryption",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1589301843
    },
    "payload": {
        "ire": {
            "auto_mode": 0,
            "sa_tradeoff": 0.5,
            "sp_tradeoff": 3
        },
        "irg": {
            "cost": {
                "firewall": 1,
                "patch": 3
            },
            "hosts": [
                {
                    "impact": "Negligible",
                    "name": "pfsense"
                },
                {
                    "id": "10000000-0000-0000-0000-000000000001",
                    "impact": "Negligible",
                    "name": "host-000C292272F2"
                },
                {
                    "id": "20000000-0000-0000-0000-000000000002",
                    "impact": "Negligible",
                    "name": "host-000c29c5f1ce"
                }
            ]
        },
        "metadata": {
            "api": "3.2.1",
            "message": "Hosts configuration was successfully retrieved.",
            "status": "OK"
        }
    },
    "trailer": {
        "signature": "mmw5vbWrUcPdQN+E0OPLLN1Y9ekQAobwXTDQLOmEgeuO1rLl/PDRpvvr9BSzpwrVoDgeWquHRgRFiRZdg6bFx+wmTr7QPa2ZEFV3bCDZdLsxG5vBvp/lgmgGXO661hSBbv07z2EHUWTCcTE2BTaThQREddsZONyoCrzJrHZaXJIn1Kejkhc4Dr5ZDtl7JZzUoRHhQXtVxqJcLnLnRsJ15WGq6p199Oeo4Zjo7O7UOQTH039aVzF/njphBTIvW6DokHuH85lAwDDBYZsmzfURx4yEJnUdbIiFRQH1vbhawySVfLHognYjyCgFgpxLNgBnvbzmcysRa1XAFiZUfvNLo4KUun/r59KRrUzMoLvPKCy4vkK5Jxjxq7wopjY4/P1YYR39dk7uert0GcY7suJUmbpgPgCuPLF/R39dzamqHPKJCScbKmkdlGU8dn1dzlzg9jZ9/8Zl0C/JViHIBtGo0ARmBsX+dv3305H98eNhho9mn3+HiUPDgB2Ktc1YnQqreghyejR72BYQXUV0+huDToBMemJSa+JhHbJPt6pUoRv2ZbUDjaPNEmZ0BtQlg8I4WPWrw/qprHX2M5+W00GnpIaGmEYzwHQgTwhrgDMNpCR2GNlhWskU+C+wO3cKl6EuRrsGjMi+O264q8c/ahdR+cJakpeNCgH219wdZzM1c1s="
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "9d5cda49-ece2-40e8-9cda-49ece2e0e818",
        "msg_topic": "SOHO.Config",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586489598
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Hosts list wasn't produced. Check the iRG Server logs for the stacktrace. </summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "7ab9692d-1552-4085-b969-2d1552c085f9",
        "msg_topic": "SOHO.Config",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586490104
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, check the iRG Server logs for the stacktrace.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 6 - Set the list of hosts and their security requirements
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/config`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/config < host-config.json
```

* The iRG Server only considers the data in the optional `irg` structure.
* The `payload/irg/hosts/{host}/id` field is optional.
* The `impact` field accepts the following values: Negligible (1), Minor (2), Normal (3), Severe (4), Catastrophic (5).

<details>
<summary>Request Data:</summary>

```json
{
    "header": {
        "source": "ps1234.cybertrust.eu",
        "msg_topic": "SOHO.Config",
        "msg_id": "dc542088-d3a7-4cb9-9420-88d3a75cb9ac",
        "cor_id": "",
        "timestamp": 1588704659736,
        "sign_alg": "sha256WithRSAEncryption"
    },
    "payload": {
        "config": {
            "irg": {
                "hosts": [
                    {
                        "name": "pfsense",
                        "impact": "Negligible"
                    },
                    {
                        "id": "10000000-0000-0000-0000-000000000001",
                        "name": "host-000C292272F2",
                        "impact": "Negligible"
                    },
                    {
                        "id": "20000000-0000-0000-0000-000000000002",
                        "name": "host-000c29c5f1ce",
                        "impact": "Negligible"
                    }
                ],
                "cost": {
                    "patch": 3,
                    "firewall": 1
                }
            },
            "ire": {
                "auto_mode": 0,
                "sa_tradeoff": 2,
                "sp_tradeoff": 3
            }
        },
        "_type": "cybertrust.smarthome"
    },
    "trailer": {
        "signature": ""
    }
}
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "dc542088-d3a7-4cb9-9420-88d3a75cb9ac",
        "msg_id": "09261c2a-dd73-413f-a61c-2add73013fc9",
        "msg_topic": "SOHO.Config",
        "sign_alg": "sha256WithRSAEncryption",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1589292435
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Hosts configuration was successfully loaded.",
            "status": "OK"
        }
    },
    "trailer": {
        "signature": "Pagsqrcpcq71Y7xaGtZ/RLtM9CbT2BSGJZbHW0JinV0q2vRWle9Yy8S8ZX+Lr2Gic1iQYkQzMu7G0AdxHjy+YJv6bZLd8cmLnipCyYk3kpXfiFjIhH3bnRAb16tEOzGCJPAzyjQkFqnfsMShZlAJbZGlbRgP2idzXmA0VBAM5iTg0FsoGw+nHKNd/aKU071Nv8hm4QV7JdblUpLmDqe+z4gKzHYHgigCDV3NrGKBc2VGEmIE2vdMcuAPz2pvPb1sRodCg2GutYeFq5KDOhcjcbxaCizh8Tygs7VaNapY4Pnl1BeEJKcrBFTBxHCIauf1a93/PmdQ0DdgW4jCL9dKVR8+DGe2EBBrrlhp7AQDfqME1bQfLMNmKnCWGNxhdrqStjVeLgMifrmTJPkyzK9PGoRXybsLmxtHar8VVfehidaB4hPB0EbXyT6Qov2s6L5TuHfczef5Zokst98BGwY7hsmsOA30tMcFAblrOqepzhYvkmsXm5ilhXT03dk1LbW5S1i40RPbg6p1tILFWiibMPjAbNZpzlUwrIBivlagyqzFZHXWMn3/3Aft5p9A9+TJx952SWtKarE40+WVFwOq1QO8qCAsWDZxE/sbl9B6SfaRLYysaYsOW5SIh9nynlrE5GH5fuLOXWN+eNiCvAwT6k8ikaAZB/wFH9ry83acNEc="
    }
}
```

</details>

<details>
<summary>Response (if the irg structure is missing):</summary>

```json
{
    "header": {
        "cor_id": "dc542088-d3a7-4cb9-9420-88d3a75cb9ac",
        "msg_id": "e8dac0f1-b9e1-41f4-9ac0-f1b9e191f44d",
        "msg_topic": "SOHO.Config",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588640991
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Message received, but the irg JSON structure is missing. No actions performed.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "0cb789c6-0985-43a4-b789-c60985d3a4a2",
        "msg_topic": "SOHO.Config",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586490350
    },
    "payload": {    
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "353d32b1-3676-413c-bd32-b13676a13caf",
        "msg_topic": "SOHO.Config",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586490641
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 7 - Set the networks (in CIDR format) to be considered when constructing the network topology
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/net-ip`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/net-ip < net-ip.json
```

<details>
<summary>Request Data:</summary>

```json
[
        "10.0.10.0/24"
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "fddfd130-d0e6-4797-9fd1-30d0e6879703",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641160
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The considered networks list has been successfully loaded.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "ab0cd98d-4cb1-40ee-8cd9-8d4cb1d0ee20",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586490712
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 8 - Upload the vulnerability scan report results
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/vuln-scan-report`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/vuln-scan-report < vuln-scan.json
```

<details>
<summary>Request Data:</summary>

```json
{
    "nmap": {
        "command_line": "nmap -oX - -p 1-1000 --min-rate 200, --max-rtt-timeout 100ms -sV --script vulners 192.168.11.1/24",
        "scaninfo": {
           "tcp": {
                "method": "connect",
                "services": "1-1000"
            }
        },
        "scanstats": {
            "timestr": "Fri May  8 15:25:56 2020",
            "elapsed": "14.49",
            "uphosts": "7",
            "downhosts": "249",
            "totalhosts": "256"
            }
      },
    "scan": [
        {
            "hostnames": [{
                "name": "_gateway",
                "type": "PTR"
            }],
            "addresses": {
                "ipv4": "192.168.11.1"
            },
            "vendor": {
            },
            "status": {
                "state": "up",
                "reason": "conn-refused"
            }
        },
        {
            "hostnames": [{
                "name": "",
                "type": ""
            }],                                                                                                                                                                              
            "addresses": {
                "ipv4": "192.168.11.3"
            },
            "vendor": {
            },
            "status": {
                "state": "up",
                "reason": "syn-ack"
            },
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.5",
                    "extrainfo": "protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:openbsd:openssh:7.5",
                    "script": {
                        "vulners": "  cpe::openbsd:openssh:7.5:      CVE-2018-15919 5.0 https://vulners.com/cve/CVE-2018-15919     CVE-2017-15906 5.0 https://vulners.com/cve/CVE-2017-15906"
                        }
                 },
                 "53": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "domain",
                    "product": "dnsmasq",
                    "version": "2.79",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:thekelleys:dnsmasq:2.79",
                    "script": {
                        "vulners": "  cpe::thekelleys:dnsmasq:2.79:      CVE-2019-14834 4.3 https://vulners.com/cve/CVE-2019-14834"
                    }
                 },
                 "80": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "http",
                    "product": "nginx",
                    "version": "",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:igor_sysoev:nginx",
                    "script": {
                        "http-server-header": "nginx"
                    }
                 }
            }
        },
        {
            "hostnames": [{
                "name": "", "type": ""
            }],
            "addresses": {
                "ipv4": "192.168.11.4"
            },
            "vendor": {
            },
            "status": {
                "state": "up",
                "reason": "conn-refused"
            },
            "tcp": {
                "53": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "domain",
                    "product": "dnsmasq",
                    "version": "2.79",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:thekelleys:dnsmasq:2.79",
                    "script": {
                        "vulners": "  cpe::thekelleys:dnsmasq:2.79:      CVE-2019-14834 4.3 https://vulners.com/cve/CVE-2019-14834"
                    }
                }
            }
        },
        {
            "hostnames": [{
                "name": "", "type": ""
            }],
            "addresses": {
                "ipv4": "192.168.11.12"
            },
            "vendor": {
            },
            "status": {
                "state": "up", "reason": "conn-refused"
            },
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "Dropbear sshd",
                    "version": "2015.67",
                    "extrainfo": "protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel"
                }
            }
        },
        {
            "hostnames": [{
                "name": "", "type": ""
            }],
            "addresses": {
                "ipv4": "192.168.11.13"
            },
            "vendor": {
            },
            "status": {
                "state": "up", "reason": "conn-refused"
            },
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
                    "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel"
                }
            }
        },
        {
            "hostnames": [{
                "name": "A04Gtest",
                "type": "PTR"
            }],
            "addresses": {
                "ipv4": "192.168.11.23"
            },
            "vendor": {
            },
            "status": {
                "state": "up",
                "reason": "conn-refused"
            },
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.6p1 Ubuntu 4ubuntu0.3",
                    "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel"
                }
            }
        },
        {
            "hostnames": [{
                "name": "", "type": ""
            }],
            "addresses": {
                "ipv4": "192.168.11.25"
            },
            "vendor": {
            },
            "status": {
                "state": "up", "reason": "conn-refused"
            },
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "Dropbear sshd",
                    "version": "2015.67",
                    "extrainfo": "protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel"
                }
            }
        }
    ]
}
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "1a294ff1-909c-4a22-a94f-f1909c3a22d5",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641346
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The vulnerability report was successfully loaded.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "06f021b0-63ed-4676-b021-b063edd67603",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586490768
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: OpenVAS XML could not be generated. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "13665176-e8dd-4c15-a651-76e8dd2c15bb",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491070
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "OpenVAS XML could not be generated.",
            "status": "ERROR"
        }
    }
}
```

</details>


---

### 9 - Upload the host list, incl. network interface information
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/hosts-interfaces`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/hosts-interfaces < hosts-interfaces.json
```

<details>
<summary>Request Data:</summary>

```json
[
    {
        "connected_to_wan": true,
        "hostname": "pfsense",
        "interface_name": "em0",
        "ip_address": "10.0.10.1"
    },
    {
        "connected_to_wan": true,
        "hostname": "host-000C292272F2",
        "interface_name": "fa0",
        "ip_address": "10.0.10.110"
    },
    {
        "connected_to_wan": true,
        "hostname": "host-000c29c5f1ce",
        "interface_name": "fa0",
        "ip_address": "10.0.10.105"
    }
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "733d46b9-724d-415d-bd46-b9724d015dda",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641415
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The hosts-interfaces list has been successfully loaded.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "5a9c8cc0-7021-4107-9c8c-c0702171075e",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491115
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, hosts-interfaces.csv could not be created. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "e548c420-6379-4e3f-88c4-2063799e3f2d",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491306
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, hosts-interfaces.csv could not be created.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 10 - Upload the vlans list
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/vlans`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/vlans < vlans.json
```

<details>
<summary>Request Data:</summary>

```json
[
    {
        "address": "10.0.10.0",
        "gateway": "10.0.10.1",
        "name": "VLAN00",
        "netmask": "24"
    }
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "131a1070-1bf6-4735-9a10-701bf6373574",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641694
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The vlans list has been successfully loaded.",
            "status": "OK"
        },
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "dffda74b-78f4-4a78-bda7-4b78f4ba7846",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491351
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, vlans.csv could not be created. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "c0052f13-804e-4f57-852f-13804e1f57e8",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586143582
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, vlans.csv could not be created.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 11 - Upload the network flow matrix
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/flow-matrix`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/flow-matrix < flow-matrix.json
```

<details>
<summary>Request Data:</summary>

```json
[
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "35009"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "35009",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "48220"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "40709"
    },
    {
        "destination": "10.0.10.1",
        "destination_port": "9594",
        "protocol": "TCP",
        "source": "10.0.10.105",
        "source_port": "40178"                                                                                                                                                               
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "48220",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "40709",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "216.58.210.46",
        "destination_port": "443",
        "protocol": "TCP",
        "source": "10.0.10.105",
        "source_port": "36490"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "36490",
        "protocol": "TCP",
        "source": "216.58.210.46",
        "source_port": "443"
    },
    {
        "destination": "216.58.210.42",
        "destination_port": "443",
        "protocol": "TCP",
        "source": "10.0.10.105",
        "source_port": "42440"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "42440",
        "protocol": "TCP",
        "source": "216.58.210.42",
        "source_port": "443"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "55203"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "55203",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "60257"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "37226",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "37226"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "60257",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "216.58.211.165",
        "destination_port": "443",
        "protocol": "TCP",
        "source": "10.0.10.105",
        "source_port": "45144"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "45144",
        "protocol": "TCP",
        "source": "216.58.211.165",
        "source_port": "443"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "41150",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "41150"
    },
    {
        "destination": "35.222.85.5",
        "destination_port": "80",
        "protocol": "TCP",
        "source": "10.0.10.105",
        "source_port": "60720"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "60720",
        "protocol": "TCP",
        "source": "35.222.85.5",
        "source_port": "80"
    },
    {
        "destination": "10.0.10.105",
        "destination_port": "55697",
        "protocol": "UDP",
        "source": "8.8.8.8",
        "source_port": "53"
    },
    {
        "destination": "8.8.8.8",
        "destination_port": "53",
        "protocol": "UDP",
        "source": "10.0.10.105",
        "source_port": "55697"
    }
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "c56dda1b-4e0b-4aa3-adda-1b4e0b9aa33c",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641762
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The flow matrix was successfully loaded.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "5669c5f6-cf81-4d4a-a9c5-f6cf81ed4ad5",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491440
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, flow-matrix.csv could not be created. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "b8367244-18ac-408c-b672-4418ac708ca6",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586143690
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, flow-matrix.csv could not be created.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 12 - Upload the routing tables
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/routing`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/topology/routing < routing-tables.json
```

<details>
<summary>Request Data:</summary>

```json
[
    {
        "destination": "default",
        "gateway": "10.0.20.1",
        "hostname": "pfsense",
        "interface": "em1",
        "mask": ""
    },
    {
        "destination": "10.0.10.0",
        "gateway": "10.0.10.1",
        "hostname": "pfsense",
        "interface": "em0",
        "mask": "255.255.255.0"
    }
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "a114604c-d107-4e45-9460-4cd107fe456e",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641979
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The routing table was successfully loaded.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f75149db-84e7-4d47-9149-db84e7ad47de",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588641961
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, routing.csv could not be created. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "377e27a6-5cc3-4b73-be27-a65cc3db7386",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586143797
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, routing.csv could not be created.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 13 - System initialization, generates the attack graph with on-disk data
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/initialize`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/initialize
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "239114f4-d458-4036-9114-f4d458e036d7",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588642032
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The initialization procedure was successful.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, couldn't generate the topology XML. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "3c02c5b1-b23a-4be4-82c5-b1b23a2be4f2",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586491839
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, couldn't generate the topology XML.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the attack graph is empty. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "ae9e0e9a-b181-4050-9e0e-9ab181405055",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586492251
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the attack graph is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON output for the iRE could not be generated. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "e6d7c9e3-9eb3-4839-97c9-e39eb38839a9",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586488875
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON output for the iRE could not be generated.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 14 - System initialization, generates the attack graph with the provided XML topology
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/initialize`

```bash
curl -X POST -H "Content-Type: multipart/form-data" -F "file=@./03.xml" http://127.0.0.1:10000/ag-engine-server/rest/json/v2/initialize
```

<details>
<summary>Request Data:</summary>

```json
<topology>
  <machine>
    <name>pfsense</name>
    <security_requirement>1</security_requirement>
    <interfaces>
      <interface>
        <name>em0</name>
        <ipaddress>10.0.10.1</ipaddress>
        <vlan>
          <name>VLAN00</name>
          <label>VLAN00</label>
        </vlan>
        <directly-connected>
          <internet />
        </directly-connected>
      </interface>
    </interfaces>
    <services>
      <service>
        <name>openssh ssh</name>
        <ipaddress>10.0.10.1</ipaddress>
        <protocol>tcp</protocol>
        <port>22</port>
        <vulnerabilities>
          <vulnerability>
            <type>remoteExploit</type>
            <cve>CVE-2018-15919</cve>
            <goal>privEscalation</goal>
            <cvss>5.0</cvss>
          </vulnerability>
          <vulnerability>
            <type>remoteExploit</type>
            <cve>CVE-2017-15906</cve>
            <goal>privEscalation</goal>
            <cvss>5.0</cvss>
          </vulnerability>
        </vulnerabilities>
      </service>
      <service>
        <name>nginx http</name>
        <ipaddress>10.0.10.1</ipaddress>
        <protocol>tcp</protocol>
        <port>80</port>
      </service>
      <service>
        <name>dnsmasq domain</name>
        <ipaddress>10.0.10.1</ipaddress>
        <protocol>tcp</protocol>
        <port>53</port>
      </service>
    </services>
    <routes>
      <route>
        <destination>0.0.0.0</destination>
        <mask>0.0.0.0</mask>
        <gateway>10.0.10.1</gateway>
        <interface>em0</interface>
      </route>
      <route>
        <destination>10.0.10.0</destination>
        <mask>255.255.255.0</mask>
        <gateway>10.0.10.1</gateway>
        <interface>em0</interface>
      </route>
    </routes>
  </machine>
  <machine>
    <name>host-000C292272F2</name>
    <security_requirement>1</security_requirement>
    <interfaces>
      <interface>
        <name>fa0</name>
        <ipaddress>10.0.10.110</ipaddress>
        <vlan>
          <name>VLAN00</name>
          <label>VLAN00</label>
        </vlan>
        <directly-connected>
          <internet />
        </directly-connected>
      </interface>
    </interfaces>
    <services />
    <routes>
      <route>
        <destination>0.0.0.0</destination>
        <mask>0.0.0.0</mask>
        <gateway>10.0.10.1</gateway>
        <interface>fa0</interface>
      </route>
    </routes>
  </machine>
  <machine>
    <name>host-000c29c5f1ce</name>
    <security_requirement>1</security_requirement>
    <interfaces>
      <interface>
        <name>fa0</name>
        <ipaddress>10.0.10.105</ipaddress>
        <vlan>
          <name>VLAN00</name>
          <label>VLAN00</label>
        </vlan>
        <directly-connected>
          <internet />
        </directly-connected>
      </interface>
    </interfaces>
    <services>
      <service>
        <name>wsgiserver/0.2 cpython/3.6.8 http-alt</name>
        <ipaddress>10.0.10.105</ipaddress>
        <protocol>tcp</protocol>
        <port>8000</port>
      </service>
      <service>
        <name>openssh ssh</name>
        <ipaddress>10.0.10.105</ipaddress>
        <protocol>tcp</protocol>
        <port>22</port>
      </service>
    </services>
    <routes>
      <route>
        <destination>0.0.0.0</destination>
        <mask>0.0.0.0</mask>
        <gateway>10.0.10.1</gateway>
        <interface>fa0</interface>
      </route>
    </routes>
  </machine>
  <flow-matrix>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>35009</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>35009</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>48220</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>40709</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination resource="10.0.10.1" type="IP" />
      <source_port>40178</source_port>
      <destination_port>9594</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>48220</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>40709</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>36490</source_port>
      <destination_port>443</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>443</source_port>
      <destination_port>36490</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>42440</source_port>
      <destination_port>443</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>443</source_port>
      <destination_port>42440</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>55203</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>55203</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>60257</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>37226</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>37226</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>60257</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>45144</source_port>
      <destination_port>443</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>443</source_port>
      <destination_port>45144</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>41150</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>41150</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>60720</source_port>
      <destination_port>80</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>80</source_port>
      <destination_port>60720</destination_port>
      <protocol>TCP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source type="INTERNET" />
      <destination resource="10.0.10.105" type="IP" />
      <source_port>53</source_port>
      <destination_port>55697</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
    <flow-matrix-line>
      <source resource="10.0.10.105" type="IP" />
      <destination type="INTERNET" />
      <source_port>55697</source_port>
      <destination_port>53</destination_port>
      <protocol>UDP</protocol>
    </flow-matrix-line>
  </flow-matrix>
</topology>
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "8336eef7-887d-43c3-b6ee-f7887d73c35f",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588642104
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The initialization procedure was successful.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, failed to store the topology XML. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "0a17ce47-37e3-4eb1-97ce-4737e30eb170",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586143927
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, failed to store the topology XML.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the attack graph is empty. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "ae9e0e9a-b181-4050-9e0e-9ab181405055",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586492251
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the attack graph is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: JSON output for the iIRE could not be generated. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "e6d7c9e3-9eb3-4839-97c9-e39eb38839a9",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586488875
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON output for the iRE could not be generated.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 15 - Get the MulVAL-generated attack graph
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph
```

The NULL UUID (`00000000-0000-0000-0000-000000000000`) fields in this example are for demonstration purposes only. If a UUID is not assigned to a host, the field `id` does not appear in the `associations` structure for this specific host (note the pfsense host without a UUID).

More example responses are available at `./attack-graph-generator/generated-topologies`.

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "7e902034-a29f-43dc-9020-34a29fe3dc83",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588642233
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The MulVAL attack graph was successfully retrieved.",
            "status": "OK"
        },
        "attack_graph": {
            "arcs": [
                {
                    "dst": 2,
                    "prob": 1,
                    "src": 3
                },
                {
                    "dst": 1,
                    "prob": 1,
                    "src": 2
                },
                {
                    "dst": 5,
                    "prob": 1,
                    "src": 6
                },
                {
                    "dst": 4,
                    "prob": 1,
                    "src": 5
                },
                {
                    "dst": 8,
                    "prob": 1,
                    "src": 9
                },
                {
                    "dst": 7,
                    "prob": 1,
                    "src": 8
                },
                {
                    "dst": 17,
                    "prob": 1,
                    "src": 18
                },
                {
                    "dst": 16,
                    "prob": 1,
                    "src": 17
                },
                {
                    "dst": 15,
                    "prob": 1,
                    "src": 16
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 21
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 22
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 23
                },
                {
                    "dst": 19,
                    "prob": 1,
                    "src": 20
                },
                {
                    "dst": 15,
                    "prob": 1,
                    "src": 19
                },
                {
                    "dst": 14,
                    "prob": 1,
                    "src": 15
                },
                {
                    "dst": 13,
                    "prob": 1,
                    "src": 14
                },
                {
                    "dst": 13,
                    "prob": 1,
                    "src": 24
                },
                {
                    "dst": 13,
                    "prob": 1,
                    "src": 25
                },
                {
                    "dst": 13,
                    "prob": 1,
                    "src": 26
                },
                {
                    "dst": 13,
                    "prob": 1,
                    "src": 4
                },
                {
                    "dst": 12,
                    "prob": 1,
                    "src": 13
                },
                {
                    "dst": 31,
                    "prob": 1,
                    "src": 18
                },
                {
                    "dst": 30,
                    "prob": 1,
                    "src": 31
                },
                {
                    "dst": 29,
                    "prob": 1,
                    "src": 30
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 21
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 34
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 35
                },
                {
                    "dst": 32,
                    "prob": 1,
                    "src": 33
                },
                {
                    "dst": 29,
                    "prob": 1,
                    "src": 32
                },
                {
                    "dst": 28,
                    "prob": 1,
                    "src": 29
                },
                {
                    "dst": 27,
                    "prob": 1,
                    "src": 28
                },
                {
                    "dst": 27,
                    "prob": 1,
                    "src": 36
                },
                {
                    "dst": 27,
                    "prob": 1,
                    "src": 25
                },
                {
                    "dst": 27,
                    "prob": 1,
                    "src": 37
                },
                {
                    "dst": 27,
                    "prob": 1,
                    "src": 1
                },
                {
                    "dst": 12,
                    "prob": 1,
                    "src": 27
                },
                {
                    "dst": 11,
                    "prob": 1,
                    "src": 12
                },
                {
                    "dst": 11,
                    "prob": 1,
                    "src": 38
                },
                {
                    "dst": 11,
                    "prob": 1,
                    "src": 25
                },
                {
                    "dst": 11,
                    "prob": 1,
                    "src": 39
                },
                {
                    "dst": 10,
                    "prob": 1,
                    "src": 11
                },
                {
                    "dst": 40,
                    "prob": 1,
                    "src": 12
                },
                {
                    "dst": 40,
                    "prob": 1,
                    "src": 38
                },
                {
                    "dst": 40,
                    "prob": 1,
                    "src": 25
                },
                {
                    "dst": 40,
                    "prob": 1,
                    "src": 41
                },
                {
                    "dst": 10,
                    "prob": 1,
                    "src": 40
                }
            ],
            "associations": [
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "relevant_vertices": [
                        7,9,10,12,14,16,19,18,21,25,28,30,32,38,39,41
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "service": "openssh ssh",
                    "type": "FULL_INFO"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "type": "PARTIAL_INFO"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "type": "LIMITED_INFO"
                },
                {
                    "hostname": "host-000C292272F2",
                    "ip": "10.0.10.110",
                    "relevant_vertices": [
                        1,3,28,30,35,32,37
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "ip": "10.0.10.105",
                    "relevant_vertices": [
                        4,6,14,16,19,23,26
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        14
                    ],
                    "service": "openssh ssh",
                    "type": "FULL_INFO"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        14
                    ],
                    "type": "PARTIAL_INFO"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "relevant_vertices": [
                        14
                    ],
                    "type": "LIMITED_INFO"
                }
            ],
            "vertices": [
                {
                    "fact": "execCode('host-000C292272F2',root)",
                    "id": 1,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 2,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated('host-000C292272F2')",
                    "id": 3,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "execCode('host-000c29c5f1ce',root)",
                    "id": 4,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 5,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated('host-000c29c5f1ce')",
                    "id": 6,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "execCode(pfsense,root)",
                    "id": 7,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 8,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated(pfsense)",
                    "id": 9,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "execCode(pfsense,user)",
                    "id": 10,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 1 (remote exploit of a server program)",
                    "id": 11,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "netAccess('10.0.10.1','TCP',22)",
                    "id": 12,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 2 (multi-hop access)",
                    "id": 13,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "hacl('10.0.10.105','10.0.10.1','TCP',22)",
                    "id": 14,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 8 (Access enabled between hosts in same vlan)",
                    "id": 15,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "RULE 12 (No local filtering on this host)",
                    "id": 17,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "localAccessEnabled('10.0.10.105','10.0.10.1',_)",
                    "id": 16,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "ipInSameVLAN('10.0.10.105','10.0.10.1')",
                    "id": 19,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "defaultLocalFilteringBehavior('10.0.10.1',allow)",
                    "id": 18,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "isInVlan('10.0.10.1','VLAN00')",
                    "id": 21,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 7 (Interfaces are in the same vlan)",
                    "id": 20,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "isInVlan('10.0.10.105','VLAN00')",
                    "id": 23,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "\\==('10.0.10.105','10.0.10.1')",
                    "id": 22,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "hasIP(pfsense,'10.0.10.1')",
                    "id": 25,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "\\==('host-000c29c5f1ce',pfsense)",
                    "id": 24,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 2 (multi-hop access)",
                    "id": 27,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "hasIP('host-000c29c5f1ce','10.0.10.105')",
                    "id": 26,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 8 (Access enabled between hosts in same vlan)",
                    "id": 29,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "hacl('10.0.10.110','10.0.10.1','TCP',22)",
                    "id": 28,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 12 (No local filtering on this host)",
                    "id": 31,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "localAccessEnabled('10.0.10.110','10.0.10.1',_)",
                    "id": 30,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "\\==('10.0.10.110','10.0.10.1')",
                    "id": 34,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "isInVlan('10.0.10.110','VLAN00')",
                    "id": 35,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "ipInSameVLAN('10.0.10.110','10.0.10.1')",
                    "id": 32,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 7 (Interfaces are in the same vlan)",
                    "id": 33,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "networkServiceInfo('10.0.10.1','openssh ssh','TCP',22,user)",
                    "id": 38,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "vulExists(pfsense,'CVE-2017-15906','openssh ssh',remoteExploit,privEscalation)",
                    "id": 39,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "\\==('host-000C292272F2',pfsense)",
                    "id": 36,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "hasIP('host-000C292272F2','10.0.10.110')",
                    "id": 37,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 1 (remote exploit of a server program)",
                    "id": 40,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "vulExists(pfsense,'CVE-2018-15919','openssh ssh',remoteExploit,privEscalation)",
                    "id": 41,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                }
            ]
        }
    }
}
```

</details>

The `type` fields of the `associations` structure indicate the precision of the association (between topology/network hosts and attack graph vertices):
* `"type": "FULL_INFO"`: Contains information about a specific **IP**, **Hostname**, **Port**, **Protocol** and **Service**.
* `"type": "PARTIAL_INFO"`: Contains information about a specific **IP**, **Hostname**, **Port** and **Protocol**.
* `"type": "LIMITED_INFO"`: Contains information about a specific **IP**, **Hostname** and **Port** (for all possible protocols: TCP, UDP, etc.)
* `"type": "IP_ONLY"`: Contains information about a specific **IP** and **Hostname** (for all possible ports, protocols and services).

With: FULL_INFO ⊆ PARTIAL_INFO ⊆ LIMITED_INFO ⊆ IP_ONLY

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "ca1a0e47-a673-4d58-9a0e-47a6735d585e",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586493104
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 16 - Get risk ratings for each network host.
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/risk`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/risk
```

If a UUID is not assigned to a host, the field `id` does not appear in the structure for the specific host (note the pfsense host without a UUID).

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "77ed2a65-4825-468a-ad2a-654825b68a8d",
        "msg_topic": "Response.Risk",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588642498
    },
    "payload": {
        "hosts": [
            {
                "ip": "10.0.10.1",
                "name": "pfsense",
                "risk": 1
            },
            {
                "id": "10000000-0000-0000-0000-000000000001",
                "ip": "10.0.10.110",
                "name": "host-000C292272F2",
                "risk": 1
            },
            {
                "id": "20000000-0000-0000-0000-000000000002",
                "ip": "10.0.10.105",
                "name": "host-000c29c5f1ce",
                "risk": 0.9988666346558449
            }
        ],
        "metadata": {
            "api": "3.2.1",
            "message": "Smart home risks were successfully calculated.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "d47460c4-8d36-4f1a-b460-c48d366f1a11",
        "msg_topic": "Response.Risk",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586493124
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Internal error, check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "cfcfcdbe-0a2a-4382-8fcd-be0a2a93822b",
        "msg_topic": "Response.Risk",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586493481
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, check the iRG Server logs for the stacktrace.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 17 - Get the topological form of the attack graph
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/topological`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/topological
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "927f926b-2e63-4ef8-bf92-6b2e639ef8b9",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588642655
    },
    "payload": {
        "topological_attack_graph": {
            "arcs": [
                {
                    "dst": 2,
                    "label": "CVE-2017-15906",
                    "src": 1
                },
                {
                    "dst": 2,
                    "label": "CVE-2017-15906",
                    "src": 0
                }
            ],
            "vertices": [
                {
                    "compromised": false,
                    "id": 0,
                    "ip_addresses": [
                        "10.0.10.110"
                    ],
                    "name": "host-000C292272F2",
                    "source_of_attack": true,
                    "target": false,
                    "type": "MACHINE"
                },
                {
                    "compromised": false,
                    "id": 1,
                    "ip_addresses": [
                        "10.0.10.105"
                    ],
                    "name": "host-000c29c5f1ce",
                    "source_of_attack": true,
                    "target": false,
                    "type": "MACHINE"
                },
                {
                    "compromised": true,
                    "id": 2,
                    "ip_addresses": [
                        "10.0.10.1"
                    ],
                    "name": "pfsense",
                    "source_of_attack": true,
                    "target": false,
                    "type": "MACHINE"
                }
            ]
        },
        "metadata": {
            "api": "3.2.1",
            "message": "The topological attack graph was successfully retrieved.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "5a30647d-6d91-46c8-b064-7d6d91e6c84c",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495625
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 18 - Get all actionable remediations for the whole attack graph
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/remediations`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/remediations
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "msg_id": "dbed0796-697d-431e-ad07-96697db31e79",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1591367092
    },
    "payload": {
        "actions": [
            {
                "affected_nodes": [
                    11,39
                ],
                "node": 11,
                "solutions": [
                    {
                        "id": 1,
                        "pfsense": [
                            "easyrule block em0 10.0.10.110",
                            "easyrule block em0 10.0.10.105"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ],
                            [
                                "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ]
            },
            {
                "affected_nodes": [
                    4,5,6,13,14,15,17,16,19,20,23,22,24,26
                ],
                "node": 13,
                "solutions": [
                    {
                        "id": 2,
                        "pfsense": [
                            "easyrule block em0 10.0.10.105"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ]
            },
            {
                "affected_nodes": [
                    1,2,3,27,29,28,31,30,34,35,32,33,36,37
                ],
                "node": 27,
                "solutions": [
                    {
                        "id": 3,
                        "pfsense": [
                            "easyrule block em0 10.0.10.110"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ]
            },
            {
                "affected_nodes": [
                    40,41
                ],
                "node": 40,
                "solutions": [
                    {
                        "id": 4,
                        "pfsense": [
                            "easyrule block em0 10.0.10.110",
                            "easyrule block em0 10.0.10.105"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ],
                            [
                                "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ]
            }
        ],
        "metadata": {
            "api": "3.2.1",
            "message": "The actions to block the specified nodes were successfully generated.",
            "status": "OK"
        }
    }
}
```
</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "18999abf-383f-4a59-999a-bf383f2a592a",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495654
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "b4ec8542-7d92-45da-ac85-427d9285daf6",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586212758
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, check the iRG Server logs for the stacktrace.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 19 - Generate firewall rules to block a specific attack graph node
**POST:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/remediations/block-nodes`

```bash
curl -X POST -H "Content-Type: application/json" -d @- http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-graph/remediations/block-nodes < block-nodes.json
```

<details>
<summary>Request Data:</summary>

```json
[
    {
        "node": 28
    },
    {
        "node": 10
    },
    {
        "node": 1
    }
]
```

</details>

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "msg_id": "e8c107f5-4014-4bcb-8107-f540144bcb4a",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1591367517
    },
    "payload": {
        "actions": [
            {
                "affected_nodes": [
                    29,28,31,30,34,35,32,33
                ],
                "node": 28,
                "solutions": [
                    {
                        "id": 1,
                        "pfsense": [
                            "easyrule block em0 10.0.10.110"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ],
                "solvable": true
            },
            {
                "affected_nodes": [
                    1,2,3,4,5,6,10,11,12,13,14,15,17,16,19,18,21,20,23,22,25,24,27,26,29,28,31,30,34,35,32,33,38,39,36,37,40,41
                ],
                "node": 10,
                "solutions": [
                    {
                        "id": 2,
                        "pfsense": [
                            "easyrule block em0 10.0.10.110",
                            "easyrule block em0 10.0.10.105"
                        ],
                        "rules": [
                            [
                                "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ],
                            [
                                "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP ",
                                "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP  --dport 22:22  -j DROP "
                            ]
                        ]
                    }
                ],
                "solvable": true
            },
            {
                "node": 1,
                "solvable": false
            }
        ],
        "metadata": {
            "api": "3.2.1",
            "message": "The actions to block the specified nodes were successfully generated.",
            "status": "OK"
        }
    }
}
```

</details>

Each node may have multiple solutions, only one is necessary to block the specified node.

Each solution contains a unique ID that identifies a specific set of firewall rules (as it might be used to receive the rule set chosen by the user when in manual mode) and an array of rule pairs.
All the rules of a solution must be applied at the same time.

<details>
<summary>Error: JSON input could not be parsed. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "efde3a39-af29-46a8-9e3a-39af2956a804",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495824
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "JSON input could not be parsed.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The following ID is invalid: #.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "e9c10d16-8bcf-441e-810d-168bcf541e5a",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495851
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The following node ID is invalid: 280.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "c65025d8-a1c6-4dca-9025-d8a1c6cdca39",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495910
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "cecc039c-9940-4afd-8c03-9c99403afd7b",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586212998
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, check the iRG Server logs for the stacktrace.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 20 - Get all attack paths
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/list`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/list
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "08a36cf5-9383-418f-a36c-f59383b18fe2",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643030
    },
    "payload": {
        "attack_paths": [
            {
                "arcs": [
                    {
                        "dst": 10,
                        "src": 11
                    },
                    {
                        "dst": 11,
                        "src": 12
                    },
                    {
                        "dst": 12,
                        "src": 13
                    },
                    {
                        "dst": 13,
                        "src": 14
                    },
                    {
                        "dst": 14,
                        "src": 15
                    },
                    {
                        "dst": 15,
                        "src": 16
                    },
                    {
                        "dst": 16,
                        "src": 17
                    },
                    {
                        "dst": 17,
                        "src": 18
                    },
                    {
                        "dst": 15,
                        "src": 19
                    },
                    {
                        "dst": 19,
                        "src": 20
                    },
                    {
                        "dst": 20,
                        "src": 21
                    },
                    {
                        "dst": 20,
                        "src": 22
                    },
                    {
                        "dst": 20,
                        "src": 23
                    },
                    {
                        "dst": 13,
                        "src": 24
                    },
                    {
                        "dst": 13,
                        "src": 25
                    },
                    {
                        "dst": 13,
                        "src": 26
                    },
                    {
                        "dst": 13,
                        "src": 4
                    },
                    {
                        "dst": 4,
                        "src": 5
                    },
                    {
                        "dst": 5,
                        "src": 6
                    },
                    {
                        "dst": 12,
                        "src": 27
                    },
                    {
                        "dst": 27,
                        "src": 28
                    },
                    {
                        "dst": 28,
                        "src": 29
                    },
                    {
                        "dst": 29,
                        "src": 30
                    },
                    {
                        "dst": 30,
                        "src": 31
                    },
                    {
                        "dst": 31,
                        "src": 18
                    },
                    {
                        "dst": 29,
                        "src": 32
                    },
                    {
                        "dst": 32,
                        "src": 33
                    },
                    {
                        "dst": 33,
                        "src": 21
                    },
                    {
                        "dst": 33,
                        "src": 34
                    },
                    {
                        "dst": 33,
                        "src": 35
                    },
                    {
                        "dst": 27,
                        "src": 36
                    },
                    {
                        "dst": 27,
                        "src": 25
                    },
                    {
                        "dst": 27,
                        "src": 37
                    },
                    {
                        "dst": 27,
                        "src": 1
                    },
                    {
                        "dst": 1,
                        "src": 2
                    },
                    {
                        "dst": 2,
                        "src": 3
                    },
                    {
                        "dst": 11,
                        "src": 38
                    },
                    {
                        "dst": 11,
                        "src": 25
                    },
                    {
                        "dst": 11,
                        "src": 39
                    },
                    {
                        "dst": 10,
                        "src": 40
                    },
                    {
                        "dst": 40,
                        "src": 12
                    },
                    {
                        "dst": 40,
                        "src": 38
                    },
                    {
                        "dst": 40,
                        "src": 25
                    },
                    {
                        "dst": 40,
                        "src": 41
                    }
                ],
                "score": 0.08881578947368421
            }
        ],
        "metadata": {
            "api": "3.2.1",
            "message": "The attack paths were successfully retrieved.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "d291a2eb-3c39-4078-91a2-eb3c39407867",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586495953
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 21 - Get the number of attack paths
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/number`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/number
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "d90113b2-1911-4fc1-8113-b219114fc19a",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643069
    },
    "payload": {
        "number": 1,
        "metadata": {
            "api": "3.2.1",
            "message": "The number of attack paths was successfully retrieved.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "63d897df-fc6d-4f9e-9897-dffc6d4f9e0c",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496175
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 22 - Get the specified attack path
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "c349f52f-ac13-4ed0-89f5-2fac13bed02c",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643216
    },
    "payload": {
        "attack_path": {
            "arcs": [
                {
                    "dst": 10,
                    "src": 11
                },
                {
                    "dst": 11,
                    "src": 12
                },
                {
                    "dst": 12,
                    "src": 13
                },
                {
                    "dst": 13,
                    "src": 14
                },
                {
                    "dst": 14,
                    "src": 15
                },
                {
                    "dst": 15,
                    "src": 16
                },
                {
                    "dst": 16,
                    "src": 17
                },
                {
                    "dst": 17,
                    "src": 18
                },
                {
                    "dst": 15,
                    "src": 19
                },
                {
                    "dst": 19,
                    "src": 20
                },
                {
                    "dst": 20,
                    "src": 21
                },
                {
                    "dst": 20,
                    "src": 22
                },
                {
                    "dst": 20,
                    "src": 23
                },
                {
                    "dst": 13,
                    "src": 24
                },
                {
                    "dst": 13,
                    "src": 25
                },
                {
                    "dst": 13,
                    "src": 26
                },
                {
                    "dst": 13,
                    "src": 4
                },
                {
                    "dst": 4,
                    "src": 5
                },
                {
                    "dst": 5,
                    "src": 6
                },
                {
                    "dst": 12,
                    "src": 27
                },
                {
                    "dst": 27,
                    "src": 28
                },
                {
                    "dst": 28,
                    "src": 29
                },
                {
                    "dst": 29,
                    "src": 30
                },
                {
                    "dst": 30,
                    "src": 31
                },
                {
                    "dst": 31,
                    "src": 18
                },
                {
                    "dst": 29,
                    "src": 32
                },
                {
                    "dst": 32,
                    "src": 33
                },
                {
                    "dst": 33,
                    "src": 21
                },
                {
                    "dst": 33,
                    "src": 34
                },
                {
                    "dst": 33,
                    "src": 35
                },
                {
                    "dst": 27,
                    "src": 36
                },
                {
                    "dst": 27,
                    "src": 25
                },
                {
                    "dst": 27,
                    "src": 37
                },
                {
                    "dst": 27,
                    "src": 1
                },
                {
                    "dst": 1,
                    "src": 2
                },
                {
                    "dst": 2,
                    "src": 3
                },
                {
                    "dst": 11,
                    "src": 38
                },
                {
                    "dst": 11,
                    "src": 25
                },
                {
                    "dst": 11,
                    "src": 39
                },
                {
                    "dst": 10,
                    "src": 40
                },
                {
                    "dst": 40,
                    "src": 12
                },
                {
                    "dst": 40,
                    "src": 38
                },
                {
                    "dst": 40,
                    "src": 25
                },
                {
                    "dst": 40,
                    "src": 41
                }
            ],
            "score": 0.08881578947368421
        },
        "metadata": {
            "api": "3.2.1",
            "message": "The requested attack path was successfully retrieved.",
            "status": "OK"
        },
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "d9bc689f-f05b-44e3-bc68-9ff05bd4e318",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496196
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The attack path ID={id} is invalid. There are only {N} attack paths generated ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "91374480-c1c7-41cf-b744-80c1c751cfd3",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496074
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The attack path ID=10 is invalid. There are only 1 attack paths generated ID=(0 to 0).",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 23 - Get the topological form of the specified attack path
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/topological`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/topological
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "1c95dbc7-efd2-4372-95db-c7efd2f372b6",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643296
    },
    "payload": {
        "topological_attack_path": {
            "arcs": [
                {
                    "dst": 2,
                    "label": "CVE-2017-15906",
                    "src": 1
                },
                {
                    "dst": 2,
                    "label": "CVE-2017-15906",
                    "src": 0
                }
            ],
            "vertices": [
                {
                    "compromised": false,
                    "id": 0,
                    "ip_addresses": [
                        "10.0.10.110"
                    ],
                    "name": "host-000C292272F2",
                    "source_of_attack": true,
                    "target": false,
                    "type": "MACHINE"
                },
                {
                    "compromised": false,
                    "id": 1,
                    "ip_addresses": [
                        "10.0.10.105"
                    ],
                    "name": "host-000c29c5f1ce",
                    "source_of_attack": true,
                    "target": false,
                    "type": "MACHINE"
                },
                {
                    "compromised": true,
                    "id": 2,
                    "ip_addresses": [
                        "10.0.10.1"
                    ],
                    "name": "pfsense",
                    "source_of_attack": false,
                    "target": true,
                    "type": "MACHINE"
                }
            ]
        },
        "metadata": {
            "api": "3.2.1",
            "message": "The requested attack path was successfully retrieved.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "b983389c-62d0-453c-8338-9c62d0053c54",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496228
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The attack path ID={id} is invalid. There are only {N} attack paths generated ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "dec6a415-133b-4e31-86a4-15133b5e31cc",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496400
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The attack path ID=10 is invalid. There are only 1 attack paths generated ID=(0 to 0).",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 24 - Get the remediations for the specified attack path
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediations`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediations
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "491ec651-1c1a-4448-9ec6-511c1a5448aa",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643436
    },
    "payload": {
        "remediations": [
            {
                "cost": 0,
                "habit_index": 0,
                "remediation_actions": {
                    "deployable_remediation": [
                        {
                            "action": {
                                "rule": "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "pfsense"
                        },
                        {
                            "action": {
                                "rule": "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "pfsense"
                        }
                    ]
                }
            },
            {
                "cost": 0,
                "habit_index": 0,
                "remediation_actions": {
                    "deployable_remediation": [
                        {
                            "action": {
                                "rule": "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "host-000C292272F2"
                        },
                        {
                            "action": {
                                "rule": "iptables -I INPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "pfsense"
                        }
                    ]
                }
            },
            {
                "cost": 0,
                "habit_index": 0,
                "remediation_actions": {
                    "deployable_remediation": [
                        {
                            "action": {
                                "rule": "iptables -I INPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "pfsense"
                        },
                        {
                            "action": {
                                "rule": "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "host-000c29c5f1ce"
                        }
                    ]
                }
            },
            {
                "cost": 0,
                "habit_index": 0,
                "remediation_actions": {
                    "deployable_remediation": [
                        {
                            "action": {
                                "rule": "iptables -I OUTPUT -s 10.0.10.110/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "host-000C292272F2"
                        },
                        {
                            "action": {
                                "rule": "iptables -I OUTPUT -s 10.0.10.105/32 -d 10.0.10.1/32 -p TCP --dport 22:22 -j DROP",
                                "type": "firewall-rule"
                            },
                            "machine": "host-000c29c5f1ce"
                        }
                    ]
                }
            },
            {
                "cost": 0,
                "habit_index": 0,
                "remediation_actions": {
                    "deployable_remediation": [
                        {
                            "action": {
                                "patchs": {
                                    "patch": "http://seclists.org/oss-sec/2018/q3/180"
                                },
                                "type": "patch"
                            },
                            "machine": "pfsense"
                        },
                        {
                            "action": {
                                "patchs": {
                                    "patch": "https://www.openssh.com/txt/release-7.6"
                                },
                                "type": "patch"
                            },
                            "machine": "pfsense"
                        }
                    ]
                }
            }
        ],
        "metadata": {
            "api": "3.2.1",
            "message": "The remediations for the specified attack path were successfully retrieved.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "4c454cd8-ca6e-488f-854c-d8ca6ea88f96",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496265
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The attack path ID={id} is invalid. There are only {N} attack paths generated ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "4432fa27-6589-46ba-b2fa-27658966bae2",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496446
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The attack path ID=10 is invalid. There are only 1 attack paths generated ID=(0 to 0).",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the system database object is null. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "8da9ecd1-9760-44c3-a9ec-d1976024c308",
        "msg_topic": "Applicable.Mitigations",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586213983
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the system database object is null.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 25 - Simulate the specified remediation on the specified attack path and compute the new attack graph
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediation/{id}`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediation/{id}
```

If a UUID is not assigned to a host, the field `id` does not appear in the structure for the specific host (note the pfsense host without a UUID).

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "55945b1f-4676-4fd7-945b-1f46763fd725",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643581
    },
    "payload": {
        "attack_graph": {
            "arcs": [
                {
                    "dst": 2,
                    "prob": 1,
                    "src": 3
                },
                {
                    "dst": 1,
                    "prob": 1,
                    "src": 2
                },
                {
                    "dst": 5,
                    "prob": 1,
                    "src": 6
                },
                {
                    "dst": 4,
                    "prob": 1,
                    "src": 5
                },
                {
                    "dst": 8,
                    "prob": 1,
                    "src": 9
                },
                {
                    "dst": 7,
                    "prob": 1,
                    "src": 8
                },
                {
                    "dst": 17,
                    "prob": 1,
                    "src": 18
                },
                {
                    "dst": 16,
                    "prob": 1,
                    "src": 17
                },
                {
                    "dst": 15,
                    "prob": 1,
                    "src": 16
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 21
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 22
                },
                {
                    "dst": 20,
                    "prob": 1,
                    "src": 23
                },
                {
                    "dst": 19,
                    "prob": 1,
                    "src": 20
                },
                {
                    "dst": 15,
                    "prob": 1,
                    "src": 19
                },
                {
                    "dst": 31,
                    "prob": 1,
                    "src": 18
                },
                {
                    "dst": 30,
                    "prob": 1,
                    "src": 31
                },
                {
                    "dst": 29,
                    "prob": 1,
                    "src": 30
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 21
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 34
                },
                {
                    "dst": 33,
                    "prob": 1,
                    "src": 35
                },
                {
                    "dst": 32,
                    "prob": 1,
                    "src": 33
                },
                {
                    "dst": 29,
                    "prob": 1,
                    "src": 32
                }
            ],
            "associations": [
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "relevant_vertices": [
                        7,9,10,12,14,16,19,18,21,25,28,30,32,38,39,41
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "service": "openssh ssh",
                    "type": "FULL_INFO"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "type": "PARTIAL_INFO"
                },
                {
                    "hostname": "pfsense",
                    "ip": "10.0.10.1",
                    "port": 22,
                    "relevant_vertices": [
                        12,14,28,38,39,41
                    ],
                    "type": "LIMITED_INFO"
                },
                {
                    "hostname": "host-000C292272F2",
                    "id": "10000000-0000-0000-0000-000000000001",
                    "ip": "10.0.10.110",
                    "relevant_vertices": [
                        1,3,28,30,35,32,37
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "id": "20000000-0000-0000-0000-000000000002",
                    "ip": "10.0.10.105",
                    "relevant_vertices": [
                        4,6,14,16,19,23,26
                    ],
                    "type": "IP_ONLY"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "id": "20000000-0000-0000-0000-000000000002",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        14
                    ],
                    "service": "openssh ssh",
                    "type": "FULL_INFO"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "id": "20000000-0000-0000-0000-000000000002",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "protocol": "TCP",
                    "relevant_vertices": [
                        14
                    ],
                    "type": "PARTIAL_INFO"
                },
                {
                    "hostname": "host-000c29c5f1ce",
                    "id": "20000000-0000-0000-0000-000000000002",
                    "ip": "10.0.10.105",
                    "port": 22,
                    "relevant_vertices": [
                        14
                    ],
                    "type": "LIMITED_INFO"
                }
            ],
            "vertices": [
                {
                    "fact": "execCode('host-000C292272F2',root)",
                    "id": 1,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 2,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated('host-000C292272F2')",
                    "id": 3,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "execCode('host-000c29c5f1ce',root)",
                    "id": 4,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 5,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated('host-000c29c5f1ce')",
                    "id": 6,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "execCode(pfsense,root)",
                    "id": 7,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 3 (Attacker is root on his machine)",
                    "id": 8,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "attackerLocated(pfsense)",
                    "id": 9,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 8 (Access enabled between hosts in same vlan)",
                    "id": 15,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "RULE 12 (No local filtering on this host)",
                    "id": 17,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "localAccessEnabled('10.0.10.105','10.0.10.1',_)",
                    "id": 16,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "ipInSameVLAN('10.0.10.105','10.0.10.1')",
                    "id": 19,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "defaultLocalFilteringBehavior('10.0.10.1',allow)",
                    "id": 18,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "isInVlan('10.0.10.1','VLAN00')",
                    "id": 21,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 7 (Interfaces are in the same vlan)",
                    "id": 20,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "isInVlan('10.0.10.105','VLAN00')",
                    "id": 23,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "\\==('10.0.10.105','10.0.10.1')",
                    "id": 22,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "RULE 8 (Access enabled between hosts in same vlan)",
                    "id": 29,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "RULE 12 (No local filtering on this host)",
                    "id": 31,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                },
                {
                    "fact": "localAccessEnabled('10.0.10.110','10.0.10.1',_)",
                    "id": 30,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "\\==('10.0.10.110','10.0.10.1')",
                    "id": 34,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "isInVlan('10.0.10.110','VLAN00')",
                    "id": 35,
                    "init_risk": 1,
                    "metric": 1,
                    "type": "LEAF"
                },
                {
                    "fact": "ipInSameVLAN('10.0.10.110','10.0.10.1')",
                    "id": 32,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "OR"
                },
                {
                    "fact": "RULE 7 (Interfaces are in the same vlan)",
                    "id": 33,
                    "init_risk": 1,
                    "metric": 0,
                    "type": "AND"
                }
            ]
        },
        "metadata": {
            "api": "3.2.1",
            "message": "The new attack graph was successfully generated.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "aa573cdb-4e7b-4006-973c-db4e7b800689",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496291
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The attack path ID={id} is invalid. There are only {N} attack paths generated ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "d83d06ed-eb0e-4d87-bd06-edeb0e6d8700",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496556
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The attack path ID=10 is invalid. There are only 1 attack paths generated ID=(0 to 0).",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The remediation ID={id_remediation} is invalid. There are only {N} remediations for that path ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "b29a027b-b9a3-41ad-9a02-7bb9a341adc4",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496573
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The remediation ID=10 is invalid. There are only 5 remediations for that path ID=(0 to 4).",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the system database object is null. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "8e03dcaf-712a-4ae2-83dc-af712a9ae238",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586214257
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the system database object is null.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the simulated attack graph couldn't be generated. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "8e03dcaf-712a-4ae2-83dc-af712a9ae238",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586214257
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the simulated attack graph couldn't be generated.",
            "status": "ERROR"
        }
    }
}
```

</details>

---

### 26 - Validate that the specified remediation has been applied
**GET:** `http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediation/{id}/validate`

```bash
curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/attack-path/{id}/remediation/{id}/validate
```

<details>
<summary>Response:</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f2499f30-85b9-462e-899f-3085b9b62ee1",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1588643770
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The validation of the specified remediation action was successful.",
            "status": "OK"
        }
    }
}
```

</details>

<details>
<summary>Error: The monitoring object is empty. The iRG Server hasn't been initialized.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "4e31d619-277d-423c-b1d6-19277df23c90",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496316
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The monitoring object is empty.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The attack path ID={id} is invalid. There are only {N} attack paths generated ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "925e0f71-f2e5-4d22-9e0f-71f2e5cd225a",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496623
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The attack path ID=10 is invalid. There are only 1 attack paths generated ID=(0 to 0).",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: The remediation ID={id_remediation} is invalid. There are only {N} remediations for that path ID=(0 to {N-1}).</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "30f22fdb-a19b-41bf-b22f-dba19b41bfab",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586496639
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "The remediation ID=10 is invalid. There are only 5 remediations for that path ID=(0 to 4).",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the system database object is null. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f936858d-f23e-421b-b685-8df23eb21b33",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586214389
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the system database object is null.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the simulated attack graph couldn't be generated. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f936858d-f23e-421b-b685-8df23eb21b33",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586214389
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the simulated attack graph couldn't be generated.",
            "status": "ERROR"
        }
    }
}
```

</details>

<details>
<summary>Error: Internal error, the validation of the specified remediation action wasn't possible. Check the iRG Server logs for the stacktrace.</summary>

```json
{
    "header": {
        "cor_id": "",
        "msg_id": "f936858d-f23e-421b-b685-8df23eb21b33",
        "msg_topic": "Internal.iRG.Test",
        "source": "iirs1234.cybertrust.eu",
        "timestamp": 1586214389
    },
    "payload": {
        "metadata": {
            "api": "3.2.1",
            "message": "Internal error, the validation of the specified remediation action wasn't possible.",
            "status": "ERROR"
        }
    }
}
```

</details>

---
