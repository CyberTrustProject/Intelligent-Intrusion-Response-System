# iIRS Attack Graph Generator (iRG) Server

## System Requirements

It's highly recommended to use the Docker version of the iRG Server, as its dependencies are very specific and outdated. The Dockerised environment ensures the security of the host by isolating these outdated dependencies.

**1. For Docker deployment**

| Requirement | Version   | Details                                                          |
| ----------- | --------- | ---------------------------------------------------------------- |
| Docker      | > 18.09.4 | The oldest Docker version the module was tested by the dev team. |

**2. For a manual installation** (not recommended)

| Requirement                 | Version        | Details                                                                                                                      |
| --------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Debian-based OS             | Any            | A minimal Ubuntu 14.04 LTS image (phusion/baseimage:0.9.16) is used to build the Docker image.                               |
| Git                         | Most recent    | Required to clone this repository.                                                                                           |
| Java 1.7                    | 1.7.0_201      | The iRG Server is coded in Java as well as a part of MulVAL which needs this exact version.                                  |
| Apache Tomcat 7             | 7.0.52.0       | Java servlet container.                                                                                                      |
| Apache Maven 3              | 3.0.5          | The iRG Server uses Maven for building and managing any Java-based part.                                                     |
| Bouncy Castle               | 1.60           | Cryptographic library used in conjunction with the Java Cryptoraphy Architecture (JCA); while also being based upon the JCA. |
| SQLite 3                    | 3.8.2          | An SQLite DB is used to store information about vulnerabilities and their remediations.                                      |
| MulVAL                      | From this repo | Produces the attack graph, based on a set of rules, which the server parses internally in XML form.                          |
| XSB (Prolog/Datalog)        | 3.6            | Attack graph is produced based on a set of rules and input data written in Datalog. XSB is the logic engine.                 |
| gcc, g++, make, flex, bison | Most recent    | Required to build XSB and MulVAL.                                                                                            |
| Data Extraction submodule   | From this repo |                                                                                                                              |
| Python 3                    | > 3.4          | The iRE Server & Data Extraction submodule of the iRG Server are coded in Python.                                            |
| PIP for Python 3            | > 1.5          | Manages and installs the required libraries for the Data Extraction submodule.                                               |
| SQLAlchemy (Python)         | 0.9.4          | An object-relational mapper used by the Data Extraction module to manage the SQLite DB.                                      |
| netaddr (Python)            | 0.7.11         | Provides functionality for Level 3 (IPv4 & IPv6) and Level 2 (MAC) network addresses.                                        |

### Docker Deployment Instructions

#### 0. Preparation

* **The iRG Server will run on `127.0.0.1:10000`.**

```bash
# BRANCH_NAME should be set to the short name of the desired branch (e.g. 'dev'):
git clone --branch BRANCH_NAME git@gitlab.com:cybertrust/tool-development/intelligent-intrusion-response.git

# To clone the 'master' branch:
git clone git@gitlab.com:cybertrust/tool-development/intelligent-intrusion-response.git

cd ./intelligent-intrusion-response
```

#### 1. To build the Docker container

```bash
sudo docker build \
     --tag ag-engine-server ./attack-graph-generator/server/container/
```

#### 2. To run the Docker container

```bash
# To run the container on the system, with stdout & stderr connected to the current terminal:
sudo docker run --name ag-engine-server -p 10000:8080 ag-engine-server

# To remove the container after its termination:
sudo docker run --rm --name ag-engine-server -p 10000:8080 ag-engine-server

# To run the container in the background (detached mode):
sudo docker run -d --name ag-engine-server -p 10000:8080 ag-engine-server
```

#### 3. Useful Docker commands

```bash
# To get a bash session on a running container:
sudo docker exec -it ag-engine-server bash

# To review the logs of a running container (stdout & stderr):
sudo docker logs ag-engine-server

# To clear all the currently unused containers and images:
sudo docker system prune

# To remove all containers:
sudo docker rm $(sudo docker ps -a -q)

# To remove all images:
sudo docker rmi $(sudo docker images -q)
```
