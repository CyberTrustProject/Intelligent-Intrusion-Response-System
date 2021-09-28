FROM ubuntu as intermediate
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git openssh-server

RUN git clone --depth=1 git@github.com:CyberTrustProject/Intelligent-Intrusion-Response-System.git

# ---

FROM phusion/baseimage:0.9.16

CMD ["/sbin/my_init"]

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
  bison \
  flex \
  g++ \
  git \
  gcc \
  make \
  maven \
  openjdk-7-jdk \
  python-pip \
  python3-pip \
  sqlite3 \
  tomcat7 \
  wget \
  nano \
  cron \
  unzip \
  && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /data/build/
WORKDIR /data/build/
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/checksums/XSB360.tar.gz.sha256 ./XSB360.tar.gz.sha256
RUN wget http://xsb.sourceforge.net/downloads/XSB360.tar.gz && \
    sha256sum --check XSB360.tar.gz.sha256 && \
    tar xzf XSB360.tar.gz
WORKDIR /data/build/XSB/build
RUN ./configure
RUN ./makexsb
RUN cp -R /data/build/XSB/ /opt/XSB

WORKDIR /data/build/
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/mulval /data/build/mulval
WORKDIR /data/build/mulval
ENV MULVALROOT=/data/build/mulval
RUN make
RUN cp -R /data/build/mulval /opt/mulval
ENV MULVALROOT=/opt/mulval
RUN chmod -R +rwx /opt/mulval

WORKDIR /root/.remediation
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/checksums/vulnerability-remediation-database.db.sha256 ./vulnerability-remediation-database.db.sha256
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/vulnerability-remediation-database.zip ./vulnerability-remediation-database.zip
RUN unzip vulnerability-remediation-database.zip
RUN sha256sum --check vulnerability-remediation-database.db.sha256
RUN rm vulnerability-remediation-database.zip
ENV VULNERABILITY_DATABASE_PATH /root/.remediation/vulnerability-remediation-database.db

WORKDIR /data/build/
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/server /data/build/server
WORKDIR /data/build/server
RUN mvn package
RUN mv ./target/ag-engine-server*.war /var/lib/tomcat7/webapps/ag-engine-server.war

WORKDIR /root/
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/data-extraction /root/cyber-data-extraction
WORKDIR /root/cyber-data-extraction

COPY --from=intermediate /Intelligent-Intrusion-Response-System/python-pkg /root/python-pkg
RUN pip install --no-index --find-links file:///root/python-pkg -r requirements.txt

RUN cp -R /data/build/server/configuration-files/* /root/.remediation
ADD ./config.properties /root/.remediation/config.properties
ADD ./inputs /root/.remediation/inputs

RUN mkdir /root/.remediation/cost-parameters
ADD ./inputs/operational-cost-params.json /root/.remediation/cost-parameters

RUN mkdir /root/.remediation/logs

RUN mkdir /root/.remediation/crypto-keys
COPY --from=intermediate /Intelligent-Intrusion-Response-System/crypto-keys/cert.pem /root/.remediation/crypto-keys/cert.pem
COPY --from=intermediate /Intelligent-Intrusion-Response-System/crypto-keys/key.pem /root/.remediation/crypto-keys/key.pem

WORKDIR /root/
COPY --from=intermediate /Intelligent-Intrusion-Response-System/attack-graph-generator/remdb-misp /root/remdb-misp
WORKDIR /root/remdb-misp

RUN pip3 install --no-index --find-links file:///root/python-pkg -r requirements.txt

RUN cp ./update /etc/cron.d/update
RUN chmod 0644 /etc/cron.d/update
RUN crontab /etc/cron.d/update
RUN touch /var/log/cron.log
RUN cron

RUN rm -rf ~/.m2
RUN rm -rf /data/
RUN rm -rf /root/python-pkg

ENV CATALINA_BASE=/var/lib/tomcat7
ENV CATALINA_HOME=/usr/share/tomcat7
ENV CATALINA_OPTS="-Xms4096M -Xmx4096M"
RUN mkdir /var/lib/tomcat7/temp

RUN mkdir /etc/service/tomcat7
ADD tomcat7.sh /etc/service/tomcat7/run
RUN chmod a+x /etc/service/tomcat7/run

EXPOSE 8080

WORKDIR /root/.remediation
