# iIRS Attack Graph Generator (iRG) Client

## System Requirements

It's highly recommended to use the Docker version of the iRG Client, as its dependencies are very specific and outdated. The Dockerised environment ensures the security of the host by isolating these outdated dependencies.

**1. For Docker deployment**

| Requirement | Version   | Details                                                          |
| ----------- | --------- | ---------------------------------------------------------------- |
| Docker      | > 18.09.4 | The oldest Docker version the module was tested by the dev team. |

**2. For a manual installation** (not recommended)

| Requirement                 | Version        | Details                                                                                                      |
| --------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------ |
| Git                         | Most recent    | Required to clone this repository.                                                                           |
| Angular JS                  | 1.3.15 +       | Client is based on Angular JS code structure.                                                                |
| D3JS                        | Any            | Provides the graph visualization on client                                                                   |
| Bootstrap                   | 3.3.5 +        | Framework used for the responsive interface.                                                                           |

### Docker Deployment Instructions

#### 0. Preparation

* **The iRG Client will run on `127.0.0.1:8880`.**

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
     --tag ag-engine-client ./attack-graph-generator/client/container/
```
#### 2. To run the Docker image

`127.0.0.1:8880`

```bash
# To run the container on the system, with stdout & stderr connected to the current terminal:
sudo docker run --name ag-engine-client -p 8880:80 ag-engine-client

# To remove the container after its termination:
sudo docker run --rm --name ag-engine-client -p 8880:80 ag-engine-client

# To run the container in the background (detached mode):
sudo docker run -d --name ag-engine-client -p 8880:80 ag-engine-client
```

#### 3. Useful Docker commands

```bash
# To get a bash session on a running container:
sudo docker exec -it ag-engine-client bash

# To review the logs of a running container (stdout & stderr):
sudo docker logs ag-engine-client

# To clear all the currently unused containers and images:
sudo docker system prune

# To remove all containers:
sudo docker rm $(sudo docker ps -a -q)

# To remove all images:
sudo docker rmi $(sudo docker images -q)
```
