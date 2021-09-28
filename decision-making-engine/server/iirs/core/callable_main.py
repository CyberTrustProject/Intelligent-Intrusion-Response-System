import json
import logging
import os
import time
from datetime import datetime
from timeit import default_timer as timer
import iso8601
import matplotlib.pyplot as plt
import pytz
import stomp
from envs.cns_toy_env_data import init_data
from iirs.agents.pomcp_new import POMCP
from iirs.core.action_make_output import action_make_output
from iirs.core.generator_for_agent import generator
from iirs.utils.helpers import extract_belief_from_particles, extract_attack_belief
from iirs.utils.helpers import getAllactions

os.path.abspath(os.path.abspath("__iirs__"))
from signature import prepareAsyncMessage

sp_factor = 1

restarts_enabled = os.environ.get("ENABLE_RESTARTS") or None
if (restarts_enabled == "True") or (restarts_enabled == "true"):
    restarts_enabled = True
else:
    restarts_enabled = False

ignore_alerted_false = os.environ.get("IGNORE_ALERTED_FALSE") or None
if (ignore_alerted_false == "True") or (ignore_alerted_false == "true"):
    ignore_alerted_false = True
else:
    ignore_alerted_false = False

tms_risk_threshold = float(os.environ.get("TMS_THRESHOLD")) or None
if tms_risk_threshold is None:
    tms_risk_threshold = 0.4

default_max_empty_action_rounds = 5
max_empty_action_rounds = int(os.environ.get("MAX_EMPTY_ACTION_ROUNDS")) or default_max_empty_action_rounds
if restarts_enabled and (max_empty_action_rounds <= 0):
    logging.warning("[CALLABLE MAIN] Invalid value for 'max_empty_action_rounds' (= {0}), default value used.".format(
        max_empty_action_rounds))
    max_empty_action_rounds = default_max_empty_action_rounds

empty_observation_updates_enabled = os.environ.get("EMPTY_OBSERVATION_UPDATES") or None
if empty_observation_updates_enabled is not None:
    if empty_observation_updates_enabled.lower() in "true":
        empty_observation_updates_enabled = True
    else:
        empty_observation_updates_enabled = False
else:
    empty_observation_updates_enabled = False

ignore_alert_timestamps = os.environ.get("IGNORE_ALERT_TIMESTAMPS") or None
if ignore_alert_timestamps is not None:
    if ignore_alert_timestamps.lower() in "true":
        ignore_alert_timestamps = True
    else:
        ignore_alert_timestamps = False
else:
    ignore_alert_timestamps = False

ignore_tms_alerts = os.environ.get("IGNORE_TMS_ALERTS") or None
if ignore_tms_alerts is not None:
    if ignore_tms_alerts.lower() in "true":
        ignore_tms_alerts = True
    else:
        ignore_tms_alerts = False
else:
    ignore_tms_alerts = False

pomcp_model_enabled = os.environ.get("ENABLE_GT_MODEL") or None
if pomcp_model_enabled is not None:
    if pomcp_model_enabled.lower() in "true":
        pomcp_model_enabled = True
    else:
        pomcp_model_enabled = False
else:
    pomcp_model_enabled = False

cybercaptor_ip = os.environ.get("CYBER_IP")
cybercaptor_port = os.environ.get("CYBER_PORT")
cybercaptor_api_call = os.environ.get("CYBER_API_CALL")

ids_ip = os.environ.get("IDS_IP")
ids_port = os.environ.get("IDS_PORT")
ids_api_call = os.environ.get("IDS_API_CALL")

bus_prefix = os.environ.get("BUS_PREFIX")
bus_ip = os.environ.get("BUS_IP")
bus_username = os.environ.get("BUS_USER")
bus_password = os.environ.get("BUS_PASSWORD")
bus_port = os.environ.get("BUS_PORT")

global observation
observation = []

global tms_messages
global currentConsumeDate


def main(currentState, env, min_iteration, sec_avail_trade, max_procs):
    global observation
    global currentConsumeDate
    global tms_messages

    attacker_keys, alert_keys, \
    _, goal_conditions, E, \
    A, \
    p_alert_dict, \
    false_alarm_probability_by_attacker, \
    p_attacker_attempts_exploit, \
    p_attacker_succeeds_exploit, ids_mapping_info, action_json = init_data()
    assert env is not None, "Env is None"

    allGeneralActions = []
    for action in action_json["payload"]["actions"]:
        if action["global"] == True:
            allGeneralActions.append("action{0}".format(int(action["id"]) + 1))

    class MyListener(stomp.ConnectionListener):
        def process_str_alert(self, message):
            if message.startswith('\"') and message.endswith('\"'):
                json_alert = message[1:-1].replace('\\\"', '\"')
                json_alert = json.loads(json_alert)
            else:
                json_alert = json.loads(message)

            if ignore_alert_timestamps:
                return json_alert
            else:
                json_date = json_alert["timestamp"]
                json_date = iso8601.parse_date(json_date)
                timestamp = datetime.timestamp(json_date.astimezone(pytz.UTC))
                logging.debug("[BUS] Message timestamp: " + str(json_date) + " --> " + str(timestamp))

                if timestamp > currentConsumeDate:
                    return json_alert
                else:
                    logging.debug("[BUS] Alert ignored.")
                    return None

        def on_error(self, headers, message):
            pass

        def on_message(self, headers, message):
            enable_anti_congestion = load_env_boolean("ANTI_CONGESTION")
            anti_congestion_threshold = load_env_float("ALERT_CONGESTION_THRESHOLD", 1.0)

            currentTimestamp = datetime.timestamp(datetime.now(pytz.utc))
            messageTimestamp = int(headers['timestamp']) / 1000
            timestampDifference = currentTimestamp - messageTimestamp

            if (enable_anti_congestion) and (timestampDifference > anti_congestion_threshold):
                logging.debug('[BUS][ALERT] Current message ignored, difference: {0}'.format(timestampDifference))
                pass

            # event_type_filter = [ "alert", "flow", "http", "fileinfo" ]
            event_type_filter = ["alert"]
            logging.debug('[BUS] Received: {0}'.format(message))
            try:
                if message.startswith('\"{') and message.endswith('}\"'):
                    logging.debug("[BUS][ALERT] Messages and timestamp difference: 1\t{0}".format(
                        str(timestampDifference).replace('.', ',')))

                    logging.debug('[BUS] Old-style single message received.')
                    new_alert = self.process_str_alert(message)
                    if new_alert != None:
                        if new_alert["event_type"] in event_type_filter:
                            if (new_alert["event_type"] == "flow") and ignore_alerted_false:
                                if new_alert["flow"]["alerted"] == True:
                                    observation.append(new_alert)
                                    logging.debug("[BUS] Alerts stored: {0}\n".format(len(observation)))
                                else:
                                    logging.debug(
                                        "[BUS] Alert ignored, 'alerted' = {0}\n".format(new_alert["flow"]["alerted"]))
                            else:
                                observation.append(new_alert)
                                logging.debug("[BUS] Alerts stored: {0}\n".format(len(observation)))
                        else:
                            logging.debug("[BUS] Alert ignored, 'event_type' = {0}\n".format(new_alert["event_type"]))
                else:
                    alert_batch = json.loads(message)
                    logging.debug("[BUS][ALERT] Messages and timestamp difference: {0}\t{1}".format(len(alert_batch),
                                                                                                    str(timestampDifference).replace(
                                                                                                        '.', ',')))
                    for alert in alert_batch:
                        if (type(alert) == str) and alert:
                            new_alert = self.process_str_alert(alert)
                            if new_alert != None:
                                if new_alert["event_type"] in event_type_filter:
                                    if (new_alert["event_type"] == "flow") and ignore_alerted_false:
                                        if new_alert["flow"]["alerted"] == True:
                                            observation.append(new_alert)
                                            logging.debug("[BUS] Alerts stored: {0}\n".format(len(observation)))
                                        else:
                                            logging.debug("[BUS] Alert ignored, 'alerted' = {0}\n".format(
                                                new_alert["flow"]["alerted"]))
                                    else:
                                        observation.append(new_alert)
                                        logging.debug("[BUS] Alerts stored: {0}\n".format(len(observation)))
                                else:
                                    logging.debug(
                                        "[BUS] Alert ignored, 'event_type' = {0}\n".format(new_alert["event_type"]))
            except Exception as error:
                logging.error('[BUS] [Network.Alert] Exception when processing: {0}'.format(message))
                logging.exception(error)

    class MyListener2(stomp.ConnectionListener):
        def on_error(self, headers, message):
            pass

        def on_message(self, headers, message):
            logging.debug('[BUS] Received: {0}'.format(message))
            json_data = json.loads(message)
            json_data = json_data["payload"]["ire"]
            if 'sp_tradeoff' in json_data.keys():
                grade = json_data['sp_tradeoff']
                currentState.set_sp(grade)
                logging.debug('[BUS] POST:/config sp_tradeoff = {0}'.format(grade))
            if 'sa_tradeoff' in json_data.keys():
                currentState.set_tradeoff(json_data['sa_tradeoff'])
                logging.debug('[BUS] POST:/config sa_tradeoff = {0}'.format(currentState.get_tradeoff()))
            if 'auto_mode' in json_data.keys():
                currentState.set_auto_mode(json_data['auto_mode'])
                logging.debug('[BUS] POST:/config auto_mode = {0}'.format(currentState.get_auto_mode()))

    class action_listener():
        def on_error(self, headers, message):
            pass

        def on_message(self, headers, message):
            if currentState.get_auto_mode() == 0:
                msg_actions = json.loads(message)
                timestamp = msg_actions["header"]["timestamp"]
                msg_actions = msg_actions["payload"]["actions"]

                for action in msg_actions:
                    action["timestamp"] = timestamp
                    action.pop("affected_hosts", None)

                    if action["status"] == 0:
                        manual_actions_pending.append(action)
                        logging.debug("[BUS] [ACTION LISTENER] New pending action: {0}\n".format(action))
                    elif action["status"] == 1:
                        manual_actions_accepted.append(action)
                        logging.debug("[BUS] [ACTION LISTENER] New accepted action: {0}\n".format(action))
                    else:
                        pass

    class TMS_listener():
        def on_error(self, headers, message):
            pass

        def on_message(self, headers, message):
            json_tms_msg = json.loads(message)
            if ("deviceIP" in json_tms_msg["payload"]) and (not ignore_tms_alerts):
                tms_messages.append(json_tms_msg)
                logging.debug("[BUS] [TMS LISTENER] Accepted TMS message: {0}".format(json_tms_msg))
            else:
                logging.debug("[BUS] [TMS LISTENER] Ignored TMS message: {0}".format(json_tms_msg))

    currentConsumeDate = datetime.timestamp(datetime.now(pytz.utc))
    logging.debug("[CALLABLE MAIN] Initialized at: " + str(datetime.fromtimestamp(currentConsumeDate)) + " --> " + str(
        currentConsumeDate))

    start = time.time()
    conn = stomp.Connection(host_and_ports=[(bus_ip, bus_port)])
    conn.set_listener('', MyListener())
    conn.connect(bus_username, bus_password, wait=True, auto_content_length=False)
    bus_destination = '/topic/' + bus_prefix + 'Network.Alert'
    conn.subscribe(destination=bus_destination, id=1, ack='auto')

    conn2 = stomp.Connection(host_and_ports=[(bus_ip, bus_port)])
    conn2.set_listener('', MyListener2())
    conn2.connect(bus_username, bus_password, wait=True, auto_content_length=False)
    bus_destination = '/topic/' + bus_prefix + 'SOHO.Config'
    conn2.subscribe(destination=bus_destination, id=1, ack='auto')

    conn3 = stomp.Connection(host_and_ports=[(bus_ip, bus_port)])
    conn3.set_listener('', action_listener())
    conn3.connect(bus_username, bus_password, wait=True, auto_content_length=False)
    bus_destination = '/topic/' + bus_prefix + 'Response.Mitigation'
    conn3.subscribe(destination=bus_destination, id=1, ack='auto')

    conn4 = stomp.Connection(host_and_ports=[(bus_ip, bus_port)])
    conn4.set_listener('', TMS_listener())
    conn4.connect(bus_username, bus_password, wait=True, auto_content_length=False)
    bus_destination = '/topic/' + bus_prefix + 'Device.Trust.Update'
    conn4.subscribe(destination=bus_destination, id=1, ack='auto')

    allActions = getAllactions(A)
    logging.debug('[CALLABLE MAIN] AllActions = {0}\n'.format(allActions))

    manual_actions_pending = []
    manual_actions_accepted = []
    manual_actions_final = []
    tms_messages = []

    current_sp = currentState.get_sp()
    actions_num = len(allActions)

    default_no_particles = 10
    no_particles = int(os.environ.get("NO_PARTICLES")) or default_no_particles
    if no_particles <= 0:
        logging.warning(
            "[CALLABLE MAIN] Invalid value for 'no_particles' (= {0}), default value used.".format(no_particles))
        no_particles = default_no_particles

    logging.debug('[CALLABLE MAIN] sp_tradeoff = {0}'.format(current_sp))
    logging.debug('[CALLABLE MAIN] sa_tradeoff = {0}'.format(currentState.get_tradeoff()))
    logging.debug('[CALLABLE MAIN] override_bus_choice = {0}'.format(os.environ.get("GENERATOR_OVERRIDE_BUS_MSG")))
    logging.debug('[CALLABLE MAIN] compromised_threshold = {0}'.format(os.environ.get("COMPROMISED_THRESHOLD")))
    logging.debug('[CALLABLE MAIN] actions_num = {0}'.format(actions_num))
    logging.debug('[CALLABLE MAIN] allGeneralActions = {0}'.format(len(allGeneralActions)))
    logging.debug('[CALLABLE MAIN] no_particles = {0}'.format(no_particles))
    logging.debug('[CALLABLE MAIN] ignore_alerted_false = {0}'.format(ignore_alerted_false))
    logging.debug('[CALLABLE MAIN] restarts_enabled = {0}'.format(restarts_enabled))
    logging.debug('[CALLABLE MAIN] max_empty_action_rounds = {0}'.format(max_empty_action_rounds))
    logging.debug('[CALLABLE MAIN] POMCP update for empty observations = {0}'.format(empty_observation_updates_enabled))
    logging.debug('[CALLABLE MAIN] POMCP model enabled = {0}'.format(pomcp_model_enabled))
    logging.debug(
        '[CALLABLE MAIN] UI pending action timeout (ms) = {0}'.format(os.environ.get("UI_ACTION_PENDING_TIMEOUT")))
    logging.debug('[CALLABLE MAIN] tms_risk_threshold = {0}'.format(tms_risk_threshold))
    logging.debug('[CALLABLE MAIN] ignore_alert_timestamps = {0}'.format(ignore_alert_timestamps))
    logging.debug('[CALLABLE MAIN] ignore_tms_alerts = {0}'.format(ignore_tms_alerts))

    if (current_sp >= 1) and (current_sp <= 5):
        min_iteration = sp_factor * current_sp * actions_num
        currentState.set_min_iteration(min_iteration)
        logging.debug('[CALLABLE MAIN] min_iteration = {0}'.format(min_iteration))
    else:
        min_iteration = sp_factor * actions_num
        currentState.set_sp(1)
        currentState.set_min_iteration(min_iteration)
        logging.debug('[CALLABLE MAIN] sp_tradeoff out of bounds, setting to 1')
        logging.debug('[CALLABLE MAIN] min_iteration = {0}'.format(min_iteration))

    while 1:
        empty_action_rounds = 0

        G = generator(
            allActions,
            E,
            list(alert_keys.values()),
            p_attacker_attempts_exploit,
            p_attacker_succeeds_exploit,
            p_alert_dict,
            false_alarm_probability_by_attacker,
            goal_conditions,
            w=sec_avail_trade
        )
        cost_over_time = []

        fig = plt.figure(figsize=(2.7, 2.5))
        ax = fig.add_subplot(111)
        _, _, _, attack_graph = env.reset()
        env.render(mode='human')

        logging.debug("[CALLABLE MAIN] Starting a new simulated attack...")

        logging.debug("[CALLABLE MAIN] Initializing new agent.")
        received_attack_graph_tmp_file = os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"

        with open(received_attack_graph_tmp_file, "r") as f:
            att = json.load(f)

        def js_or(diction, key, alt=""):
            if key in diction:
                return diction[key]
            else:
                return alt

        def match_host_to_goal(goal_conditions):
            goal_conditions = [int(i.split("-")[1]) for i in goal_conditions]
            output = {}
            for goal in goal_conditions:
                hosts = att["payload"]["attack_graph"]['associations']
                for host in hosts:
                    if goal in host["relevant_vertices"]["SC"]:
                        output["SC-" + str(goal)] = {
                            "api": "3.0",
                            "deviceId": js_or(host, "id"),
                            "hostname": js_or(host, "hostname"),
                            "deviceIp": js_or(host, "ip"),
                            "changeType": "deviceCompromised",
                            "compromisedElements": [
                                {
                                    "compromiseType": "OS_HACK",
                                    "additionalInfo": ids_mapping_info[goal]
                                }
                            ],
                            "result": {
                                "message": "iRE alert successfully generated.",
                                "status": "OK"
                            }
                        }
                        break
            return output

        t = 0
        goal_conditions = []
        gc_use = []
        for id_ in ids_mapping_info:
            if ("execCode" in ids_mapping_info[id_]) and ("root" in ids_mapping_info[id_]):
                goal_conditions.append("SC-" + str(id_))
                gc_use.append(id_)
        goal_map = match_host_to_goal(goal_conditions)
        end = time.time()
        logging.debug("\n[TIMING] Initialization time: {0}\n".format(end - start))

        choose_global_rules = False

        logging.debug('[CALLABLE MAIN] Waiting to receive the first alerts.')
        while len(observation) <= 0:
            continue

        if not pomcp_model_enabled:
            latest_action = 'action1'

            while 1:
                logging.debug("=================================================================================")

                logging.debug("[CALLABLE MAIN] Mapping the received alerts to the graph.")
                start = time.time()
                trig_alerts, all_trig_alert_sets, _, choose_global_rules = match_alerts_to_exploits(ids_mapping_info,
                                                                                                    observation,
                                                                                                    tms_messages)
                end = time.time()
                logging.debug("[ALERT] Processed alerts: {0}".format(len(observation)))
                logging.debug("[TIMING] Alert process time: {0}\n".format(end - start))
                observation = []

                all_trig_alerts_sorted = []
                for alert_set in all_trig_alert_sets:
                    alert_sorted = prepare_alert_set(alert_set, need_tags=True, has_tags=False)
                    if alert_sorted not in all_trig_alerts_sorted:
                        all_trig_alerts_sorted.append(alert_sorted)
                logging.debug("[ALERT] Triggered alert sets: {0}\n".format(all_trig_alerts_sorted))

                env.attack_graph.reset()
                for ex_id in trig_alerts:
                    env.attack_graph.exploits["E-{0}".format(ex_id)].attempted = True

                if currentState.get_auto_mode() == 0:
                    logging.debug("[ACTION LISTENER] Pending actions: {0}, Accepted actions: {1}\n".format(
                        len(manual_actions_pending), len(manual_actions_accepted)))
                    manual_actions_pending = clear_old_actions(manual_actions_pending)
                    manual_actions_accepted = clear_old_actions(manual_actions_accepted)
                    manual_actions_final = get_accepted_actions(manual_actions_pending, manual_actions_accepted)
                    if len(manual_actions_final) == 0:
                        manual_actions_final.append("action1")
                    logging.debug("[ACTION LISTENER] Current accepted actions: {0}\n".format(manual_actions_final))
                    logging.debug("[ACTION LISTENER] Pending actions: {0}, Accepted actions: {1}\n".format(
                        len(manual_actions_pending), len(manual_actions_accepted)))

                if currentState.get_auto_mode() == 0:
                    start = time.time()

                    ex_to_block = []
                    if empty_observation_updates_enabled and (len(all_trig_alerts_sorted) == 0):
                        logging.debug("[CALLABLE MAIN] Update rounds: {0}".format(len(manual_actions_final)))
                        for ui_act in manual_actions_final:
                            logging.debug("[CALLABLE MAIN] Update belief for: EMPTY + {0}".format(ui_act))
                            additional_ex_to_block = []
                            manual_actions_final.remove(ui_act)
                            for ex in additional_ex_to_block:
                                if ex not in ex_to_block:
                                    ex_to_block.append(ex)
                    else:
                        logging.debug("[CALLABLE MAIN] Update rounds: {0}".format(
                            len(all_trig_alerts_sorted) * len(manual_actions_final)))
                        for pair in all_trig_alerts_sorted:
                            for ui_act in manual_actions_final:
                                logging.debug("[CALLABLE MAIN] Update belief for: {0} + {1}".format(pair, ui_act))
                                logging.debug("[CALLABLE MAIN] Set elements: {0}".format(len(pair)))
                                additional_ex_to_block = []
                                manual_actions_final.remove(ui_act)
                                for ex in additional_ex_to_block:
                                    if ex not in ex_to_block:
                                        ex_to_block.append(ex)

                    end = time.time()
                    logging.debug("[TIMING] Belief update time: {0}\n".format(end - start))
                else:
                    logging.debug("[CALLABLE MAIN] Update rounds: {0}".format(len(all_trig_alerts_sorted)))
                    start = time.time()
                    if empty_observation_updates_enabled and (len(all_trig_alerts_sorted) == 0):
                        logging.debug("[CALLABLE MAIN] Update belief for: EMPTY")
                        ex_to_block = []
                    else:
                        for pair in all_trig_alerts_sorted:
                            logging.debug("[CALLABLE MAIN] Update belief for: {0}".format(pair))
                            logging.debug("[CALLABLE MAIN] Set elements: {0}".format(len(pair)))
                            ex_to_block = []
                    end = time.time()
                    logging.debug("[TIMING] Belief update time: {0}\n".format(end - start))

                belief_ = []
                logging.debug("[CALLABLE MAIN] Belief update: {0}\n".format(belief_))

                logging.debug("--------> {0}".format(ex_to_block))

                latest_action = match_action(allActions, allGeneralActions, ex_to_block, choose_global_rules)
                ex_to_block = allActions[latest_action]

                for ex_id in ex_to_block:
                    env.attack_graph.exploits[ex_id].blocked = True

                if latest_action != 'action1':
                    output_response = action_make_output(action_id=latest_action, response=None, json=action_json,
                                                         choose_global_rules=choose_global_rules, find_specific_id=True,
                                                         state=currentState)
                    currentState.set_action(output_response)
                    send_to_bus = prepareAsyncMessage(output_response["payload"])
                    bus_destination = '/topic/' + bus_prefix + 'Response.Mitigation'
                    conn.send(body=json.dumps(send_to_bus), destination=bus_destination)
                else:
                    logging.debug("[CALLABLE MAIN] Empty action chosen, skipping bus communications.")

                trig_alerts = prepare_alert_set(trig_alerts, need_tags=True, has_tags=False)
                triggered_alerts = {k: False for k in attack_graph.alerts.keys()}
                for i in trig_alerts:
                    triggered_alerts[i] = True
                triggered_alerts = [{'name': k, 'triggered': v} for k, v in triggered_alerts.items()]
                fig.savefig("plot.svg", format='svg')
                with open('plot.svg', 'r') as myfile:
                    plot = myfile.read()
                if len(belief_) > 0:
                    env.render(belief_state=belief_, plot=plot, alerts=triggered_alerts)
                    logging.debug("[CALLABLE MAIN] Rendered!")

        if pomcp_model_enabled:
            logging.debug("=================================================================================")

            while 1:
                if restarts_enabled and (empty_action_rounds >= max_empty_action_rounds):
                    logging.debug('[CALLABLE MAIN] Reached the max number of rounds without an action. Restarting.')
                    break

                start = time.time()
                latest_action = 'action1'
                end = time.time()
                logging.debug("\n[TIMING] Action computation time: {0}\n".format(end - start))
                list_of_nodes_to_block = allActions[latest_action]
                logging.debug("[CALLABLE MAIN] Nodes to block: {0} {1}".format(latest_action, list_of_nodes_to_block))

                if restarts_enabled and (len(list_of_nodes_to_block) <= 0):
                    empty_action_rounds += 1
                    logging.debug('[CALLABLE MAIN] {0} round(s) without an action.'.format(empty_action_rounds))
                elif restarts_enabled and (len(list_of_nodes_to_block) > 0) and (empty_action_rounds != 0):
                    empty_action_rounds = 0

                list_of_nodes_to_return = []
                for node in list_of_nodes_to_block:
                    list_of_nodes_to_return.append({'node': int(node.split('-')[1])})
                msg = list_of_nodes_to_return
                output_response = action_make_output(action_id=latest_action, response=msg, json=action_json,
                                                     choose_global_rules=choose_global_rules, state=currentState)
                currentState.set_action(output_response)
                send_to_bus = prepareAsyncMessage(output_response["payload"])
                bus_destination = '/topic/' + bus_prefix + 'Response.Mitigation'
                conn.send(body=json.dumps(send_to_bus), destination=bus_destination)
                trig_alerts, cumulative_cost, d, _ = env.step(latest_action)

                start = time.time()
                trig_alerts, all_trig_alert_sets, _, choose_global_rules = match_alerts_to_exploits(ids_mapping_info,
                                                                                                    observation)
                end = time.time()
                logging.debug("[ALERT] Processed alerts: {0}".format(len(observation)))
                logging.debug("[ALERT] Choosing from general FW rules: {0}".format(choose_global_rules))
                logging.debug("[TIMING] Alert process time: {0}\n".format(end - start))

                trig_alerts = prepare_alert_set(trig_alerts, need_tags=True, has_tags=True)

                all_trig_alerts_sorted = []
                for alert_set in all_trig_alert_sets:
                    alert_sorted = prepare_alert_set(alert_set, need_tags=True, has_tags=True)
                    if alert_sorted not in all_trig_alerts_sorted:
                        all_trig_alerts_sorted.append(alert_sorted)

                trig_alert_pairs = all_trig_alerts_sorted
                logging.debug("[ALERT] Triggered alert pairs: {0}\n".format(trig_alert_pairs))

                observation = []
                cost_over_time += [cumulative_cost]

                ax.plot(range(len(cost_over_time)),
                        cost_over_time,
                        color='b',
                        alpha=0.7,
                        linewidth=2)

                ax.set_xlim([0, 50])
                ax.set_xlabel("Sum of Discounted Costs")
                ax.set_ylim([0, 5])
                ax.set_ylabel("Time Steps")
                start = timer()
                fig.savefig("plot.svg", format='svg')
                belief_ = []

                done = False

                logging.debug("[CALLABLE MAIN] POMCP update rounds: {0}".format(len(trig_alert_pairs)))
                start = time.time()
                if empty_observation_updates_enabled and (len(trig_alert_pairs) == 0):
                    logging.debug("[CALLABLE MAIN] Update POMCP belief for: EMPTY")
                else:
                    for pair in trig_alert_pairs:
                        logging.debug("[CALLABLE MAIN] Update POMCP belief for: {0}".format(pair))
                        logging.debug("[CALLABLE MAIN] Set elements: {0}".format(len(pair)))
                end = time.time()
                logging.debug("[TIMING] Belief update time: {0}\n".format(end - start))

                triggered_alerts = {k: False for k in attack_graph.alerts.keys()}
                for i in trig_alerts:
                    triggered_alerts[i] = True

                triggered_alerts = [{'name': k, 'triggered': v} for k, v in triggered_alerts.items()]
                logging.debug("[CALLABLE MAIN] Belief update: {0}\n".format(belief_))

                with open('plot.svg', 'r') as myfile:
                    plot = myfile.read()

                if len(belief_) > 0:
                    env.render(belief_state=belief_, plot=plot, alerts=triggered_alerts)
                    logging.debug("[CALLABLE MAIN] Rendered!")
                    t += 1

                if done:
                    logging.debug("[CALLABLE MAIN] Ending Simulation.")
                    break

    env.close()
    del env


def print_belief_as_csv(belief):
    header = ""
    line = ""
    for sc in belief[0].keys():
        header += "," + sc
        line += "," + str(belief[0][sc])
    logging.debug("\n[CSV STATE]{0}\n[CSV STATE]{1}\n".format(header, line))

    header = ""
    line = ""
    for at in belief[1].keys():
        header += "," + at
        line += "," + str(belief[1][at])
    logging.debug("\n[CSV ATTACKER]{0}\n[CSV ATTACKER]{1}\n".format(header, line))


def match_alerts_to_exploits(ids_mapping_info, observation, tms_messages=None):
    trig_alerts_list = []
    trig_alerts_union = set() 
    affected_sc = set()
    choose_global_rules = True 

    affected_sc_tmp = affected_sc.copy()
    affected_sc = set()
    for sc in affected_sc_tmp:
        affected_sc.add('SC-{0}'.format(sc))

    return trig_alerts_union, trig_alerts_list, affected_sc, choose_global_rules


def prepare_alert_set(alert_set, need_tags=False, has_tags=True):
    sorted_set = set()

    if need_tags:
        for v_id in alert_set:
            sorted_set.add("AL-{0}".format(v_id))
    else:
        sorted_set = alert_set

    sorted_set = list(sorted_set)
    if has_tags:
        sorted_set.sort(key=lambda x: int(x.split("-")[1]))
    else:
        sorted_set.sort()

    return sorted_set


def match_action(all_actions, allGeneralActions, ex_to_block, choose_global_rules):
    action = 'action1'
    factor = 0.0

    logging.debug("[MATCH ACTION] choose_global_rules = {0}".format(choose_global_rules))

    logging.debug("[MATCH ACTION] {0} -> {1}".format(action, factor))
    return action


def clear_old_actions(actions):
    threshold = os.environ.get("UI_ACTION_PENDING_TIMEOUT") or None
    if threshold is not None:
        threshold = int(threshold)
        if threshold <= 0:
            threshold = 60000
    else:
        threshold = 60000

    current_time = round(time.time() * 1000)
    actions_kept = []

    for action in actions:
        interval = current_time - action["timestamp"]
        if interval <= threshold:
            actions_kept.append(action)
        else:
            logging.debug("[ACTION LISTENER] Removing action: {0} -> {1}\n".format(action, interval))

    return actions_kept


def get_accepted_actions(pending_actions, accepted_actions):
    final_list = []

    for pending in pending_actions:
        for accepted in accepted_actions:
            if (accepted["mitigation"]["id"] == pending["mitigation"]["id"]) and (
                    accepted["timestamp"] >= pending["timestamp"]):
                final_list.append("action{0}".format(accepted["mitigation"]["id"] + 1))
                pending_actions.remove(pending)
                accepted_actions.remove(accepted)

    return final_list


def load_env_boolean(variable):
    result = os.environ.get(variable) or None
    if (result == "True") or (result == "true"):
        result = True
    else:
        result = False
    return result


def load_env_float(variable, default):
    result = float(os.environ.get(variable)) or None
    if result is None:
        result = default
    return result
