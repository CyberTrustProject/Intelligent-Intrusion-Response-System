FROM python:3.6.8
WORKDIR /app
COPY . /app

COPY requirements.txt /app/requirements.txt
RUN apt-get update \
  && apt-get install -y --no-install-recommends graphviz less \
  && rm -rf /var/lib/apt/lists/* \
&& pip install --no-cache-dir pyparsing pydot
RUN pip install --trusted-host pypi.python.org -r /app/requirements.txt
RUN apt-get update && apt-get install -y lsof

RUN pip install -e iirs
RUN pip install -e simple-websocket-server-master

ENV CYBER_PORT "10000"
ENV CYBER_API_CALL "/ag-engine-server/rest/json/v2/attack-graph/remediations/block-nodes"
ENV CYBER_GET_ACTIONS "/ag-engine-server/rest/json/v2/attack-graph/remediations"
ENV TMP_GRAPH_FILE "tmp/attack_graph_received.json"
ENV IIRS_PORT "17891"
ENV IDS_IP "0.0.0.0"
ENV IDS_PORT "36010"
ENV IDS_API_CALL "/test"

ENV IGNORE_ALERT_TIMESTAMPS "True"
ENV IGNORE_TMS_ALERTS "True"

ENV ANTI_CONGESTION "True"
ENV ALERT_CONGESTION_THRESHOLD "0.5"

ENV IGNORE_ALERTED_FALSE "True"
ENV COMPROMISED_THRESHOLD "0.5"
ENV TMS_THRESHOLD "0.4"
ENV ENABLE_GT_MODEL "False"
ENV GENERATOR_POLICY "Strict"
ENV GENERATOR_OVERRIDE_BUS_MSG "False"
ENV UI_ACTION_PENDING_TIMEOUT "60000"

ENV NO_PARTICLES "10"
ENV EMPTY_OBSERVATION_UPDATES "True"
ENV FORCE_GENERAL_RULES_ONLY "False"
ENV POSTERIOR_SAMPLE_TIMEOUT "80"
ENV ENABLE_RESTARTS "True"
ENV MAX_EMPTY_ACTION_ROUNDS "3"

ENV CYBER_IP "172.17.0.1"
ENV BUS_PREFIX "5002."
ENV BUS_USER "admin"
ENV BUS_PASSWORD "admin"
ENV BUS_IP "172.17.0.1"
ENV BUS_PORT "61613"

WORKDIR /app/iirs
EXPOSE 17891
CMD ["python", "/app/iirs/api.py"]
