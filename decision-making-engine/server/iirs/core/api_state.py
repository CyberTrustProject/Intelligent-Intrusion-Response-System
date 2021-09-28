import json
import os

class state():
    def reload_json(self):
        received_attack_graph_tmp_file = os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"
        with open(received_attack_graph_tmp_file, "r") as f:
            self.att = json.load(f)

    def __init__(self):
        self._compromised = {
            "payload": {
                "api": "3.0",
                "deviceId": "",
                "hostname": "",
                "deviceIp": "",
                "changeType": "",
                "compromisedElements": [],
                "result": {
                    "message": "iRE alert successfully generated.",
                    "status": "OK"
                }
            }
        }
        self._action = {
            "payload": {
                "api": "3.0",
                "actions": [],
                "result": {
                    "message": "Decision was successfully generated",
                    "status": "OK"
                }
            }
        }
        self.parameters = {
            'auto_mode': 1,
            'min_iterations': 0,
            'sp_tradeoff': 2,
            'sa_tradeoff': 0.6,
            'max_processes': 16
        }

        received_attack_graph_tmp_file = os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"
        with open(received_attack_graph_tmp_file, "r") as f:
            self.att = json.load(f)

    def get_hosts(self):
        self.reload_json()
        output = []
        hosts = self.att["payload"]["attack_graph"]['associations']
        for host in hosts:
            if "id" not in host:
                host["id"] = ""

            found_host = False
            for entry in output:
                if host["hostname"] in entry["name"]:
                    found_host = True
                    break

            if not found_host:
                output.append({
                    "id": host["id"],
                    "name": host["hostname"],
                    "impact": "Normal",
                })

        return output

    def get_sp(self):
        return self.parameters["sp_tradeoff"]

    def get_min_iteration(self):
        return self.parameters['min_iterations']

    def get_parameters(self):
        output = {
            "payload": {
                "api": "3.0",
                "irg": {
                    "hosts": self.get_hosts(),
                    "costs": {
                        "patch": 3,
                        "firewall": 1
                    }
                },
                "ire": {
                    "auto_mode": self.parameters["auto_mode"],
                    "sa_tradeoff": self.parameters["sa_tradeoff"],
                    "sp_tradeoff": self.get_sp()
                },
                "result": {
                    "message": "Decision was successfully generated.",
                    "status": "OK"
                }
            }
        }
        return output

    def get_auto_mode(self):
        return self.parameters['auto_mode']

    def set_auto_mode(self, value):
        assert type(value) == int, "auto_mode must be int"
        self.parameters['auto_mode'] = value

    def get_tradeoff(self):
        return self.parameters['sa_tradeoff']

    def set_tradeoff(self, value):
        self.parameters['sa_tradeoff'] = value

    def get_min_iteration(self):
        return self.parameters['min_iterations']

    def set_sp(self, grade):
        assert type(grade) == int, "sp_tradeoff must be int"
        self.parameters['sp_tradeoff'] = grade

    def set_min_iteration(self, value):
        assert type(value) == int, "min_iterations must be int"
        self.parameters['min_iterations'] = value

    def get_max_processes(self):
        return self.parameters['max_processes']

    def set_max_processes(self, value):
        assert type(value) == int, "Max processes must be int"
        self.parameters['max_processes'] = value

    def get_action(self):
        return self._action

    def set_action(self, value):
        self._action = value

    def get_compromised(self):
        return self._compromised

    def set_compromised(self, value):
        self._compromised = value
