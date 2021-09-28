import json
import os
import logging

received_attack_graph_tmp_file = os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"

decisionFileLogger = logging.getLogger('decisionLogger')

with open(received_attack_graph_tmp_file, "r") as f:
    att = json.load(f)


def reload_json():
    with open(received_attack_graph_tmp_file, "r") as f:
        return json.load(f)


def get_hosts(action):
    att = reload_json()
    output = []

    hosts = att["payload"]["attack_graph"]['associations']
    af_nodes = action["affected_nodes"]
    for host in hosts:
        if "id" not in host:
            host["id"] = ""

        if set(af_nodes) & set(host["relevant_vertices"]["AL"]):
            found_host = False
            for entry in output:
                if host["hostname"] in entry["hostname"]:
                    found_host = True
                    break
            if not found_host:
                output.append({
                    "id": host["id"],
                    "hostname": host["hostname"],
                    "ip": host["ip"],
                })

    return output


def get_mitigations(action):
    decisionFileLogger.debug("[RULE] {0}".format(action["solution"]["rules"]))
    sol = action["solution"]
    return {
        "id": action["id"],
        "pfsense": sol["pfsense"],
        "rules": sol["rules"],
        "mode": "Enable"
    }


def make_action_list(relevant_actions, state):
    output = []
    for action in relevant_actions:
        placeholder = {}
        placeholder["affected_hosts"] = get_hosts(action)
        placeholder["mitigation"] = get_mitigations(action)

        if state == None:
            logging.error("[ACTION MAKE OUTPUT] state is None.")

        if state.get_auto_mode() == 0:
            placeholder["status"] = 0
        else:
            placeholder["status"] = 1

        output.append(placeholder)
    return output


def action_make_output(action_id, response, json, choose_global_rules, find_specific_id=False, state=None):
    force_general_rules = os.environ.get("FORCE_GENERAL_RULES_ONLY") or None
    if (force_general_rules == "True") or (force_general_rules == "true"):
        force_general_rules = True
    else:
        force_general_rules = False

    chosen_action_ids = []
    relevant_actions = []

    if (force_general_rules == False) and (find_specific_id == False):
        check = [i["node"] for i in response]
        for action in json["payload"]["actions"]:
            if (action["global"] == choose_global_rules) and (action["id"] not in chosen_action_ids):
                for affected_node in action["affected_nodes"]:
                    if affected_node in check:
                        relevant_actions.append(action)
                        chosen_action_ids.append(action["id"])
                        break
        if (len(chosen_action_ids) == 0) and (len(check) > 0):
            logging.debug(
                "[ACTION MAKE OUTPUT] No match found during the first round, searching all rules to find a match.")
            for action in json["payload"]["actions"]:
                if action["id"] not in chosen_action_ids:
                    for affected_node in action["affected_nodes"]:
                        if affected_node in check:
                            relevant_actions.append(action)
                            chosen_action_ids.append(action["id"])
                            break
    else:
        specific_id = int(action_id.split("action")[1]) - 1
        logging.debug("[ACTION MAKE OUTPUT] Searching for action {0}".format(specific_id))
        for action in json["payload"]["actions"]:
            if action["id"] == specific_id:
                relevant_actions.append(action)
                break

    return {
        "payload": {
            "actions": make_action_list(relevant_actions, state),
            "metadata": {
                "api": "3.0",
                "message": "Decision was successfully generated.",
                "status": "OK"
            }
        }
    }
