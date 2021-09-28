import os, sys
import requests
os.path.abspath(os.path.abspath("__iirs__"))
from core.mapper import mapper
received_attack_graph_tmp_file=os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"
os.path.abspath(os.path.abspath("__iirs__"))
cybercaptor_ip=os.environ.get("CYBER_IP") or "0.0.0.0"
cybercaptor_port=os.environ.get("CYBER_PORT") or "10000"
cybercaptor_api_call=os.environ.get("CYBER_API_CALL") or "/attack-graph/remediations/block-nodes"
cybercaptor_api_call2=os.environ.get("CYBER_GET_ACTIONS") or "/ag-engine-server/rest/json/v2/attack-graph/remediations"
ids_ip=os.environ.get("IDS_IP") or "0.0.0.0"
ids_port=os.environ.get("IDS_PORT") or "36010"
ids_api_call=os.environ.get("IDS_API_CALL") or "/test"

def init_data(leaf = None):
    exploit_keys, security_condition_keys, \
        exploit_with_edges, attacker_keys, \
            p_attempt, p_success, \
                leaf_nodes, ids_mapping_info, goal_conditions, leaf_execcode = mapper(received_attack_graph_tmp_file)
    if leaf is not None:
        return leaf_nodes, leaf_execcode
    
    r=requests.get(url="http://"+ cybercaptor_ip + ":" + cybercaptor_port + cybercaptor_api_call2)
    action_json = r.json()
    actions={}
    action_blocks_exploit = {}
    try:
        received_action_info = action_json["payload"]["actions"]
        for ind, act in enumerate(received_action_info):
            actions[ind+1] = "AC-{0}".format(ind+1)
            exploits_possibly = set(["E-{0}".format(i) for i in act["affected_nodes"]])
            exploits_ = set(exploit_keys.values())
            common = list(exploits_.intersection(exploits_possibly))
            action_blocks_exploit[actions[ind+1]] = common
    except Exception as _:
        actions[0] = "AC-0"
        action_blocks_exploit["AC-0"] = []

    alert_keys = {ind+1:"AL-{0}".format(i.split("-")[1]) for ind, i in exploit_keys.items()}

    false_alarm_probability_by_attacker = {
        i: {
            attacker_keys[1]: 0.05,
            attacker_keys[2]: 0.1,
            attacker_keys[3]: 0.1
        } for i in alert_keys.values()
    }

    def p_alert(exploit_j, attackerType):
        for _, v in exploit_keys.items():
            if v == exploit_j:
                number = v.split("-")[1]
                return {"AL-{0}".format(number): 0.4}


    exploit_alert_triggered_by_attacker = {}
    for at_type in attacker_keys.values():
        for exploit in exploit_with_edges.keys():
            if exploit not in exploit_alert_triggered_by_attacker.keys():
                exploit_alert_triggered_by_attacker[exploit] = {}
            for alert in p_alert(exploit, at_type).keys():
                if alert not in exploit_alert_triggered_by_attacker[exploit].keys():
                    exploit_alert_triggered_by_attacker[exploit][alert] = {}
                exploit_alert_triggered_by_attacker[exploit][alert][at_type] = p_alert(exploit, at_type)[alert]

    p_attacker_attempts_exploit = {}
    for attacker_type in attacker_keys.values():
        if attacker_type not in p_attacker_attempts_exploit.keys():
            p_attacker_attempts_exploit[attacker_type] = {}
        for exploit in exploit_keys.values():
            p_attacker_attempts_exploit[attacker_type][exploit] = list(p_attempt[exploit][at_type])


    p_attacker_succeeds_exploit = {}
    for attacker_type in attacker_keys.values():
        if attacker_type not in p_attacker_succeeds_exploit.keys():
            p_attacker_succeeds_exploit[attacker_type] = {}
        for exploit in exploit_keys.values():
            p_attacker_succeeds_exploit[attacker_type][exploit] = p_success[exploit][at_type]

    real_attacker = attacker_keys[1]

    return attacker_keys, alert_keys, real_attacker, goal_conditions, \
    exploit_with_edges, action_blocks_exploit, exploit_alert_triggered_by_attacker, \
    false_alarm_probability_by_attacker, p_attacker_attempts_exploit, \
    p_attacker_succeeds_exploit, ids_mapping_info, action_json