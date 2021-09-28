FROM ubuntu as intermediate
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git openssh-server

RUN git clone --depth=1 git@github.com:CyberTrustProject/Intelligent-Intrusion-Response-System.git

ARG MYAPP_FILE="./myApp_localhost.js"
COPY $MYAPP_FILE /Intelligent-Intrusion-Response-System/attack-graph-generator/client/js/myApp.js

# ---

FROM phusion/passenger-customizable:0.9.16

ENV HOME /home/app
WORKDIR /home/app

COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/client /home/app/client

WORKDIR /home/app/client

RUN rm /etc/nginx/sites-enabled/default
ADD cybercaptor-client.conf /etc/nginx/sites-available/cybercaptor-client.conf
RUN ln -s /etc/nginx/sites-available/cybercaptor-client.conf /etc/nginx/sites-enabled/cybercaptor-client.conf

RUN rm -f /etc/service/nginx/down

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 80
CMD ["/sbin/my_init"]
