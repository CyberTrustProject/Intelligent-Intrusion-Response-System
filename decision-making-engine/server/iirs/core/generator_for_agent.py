import json
import logging
import os
import random
import time
from itertools import chain, combinations

from numpy.random import binomial


class generator():
    def __init__(self,
                 actions,
                 exploits_with_edges,
                 alert_keys,
                 attacker_exploit_attempt_probabilities,
                 attacker_exploit_success_probabilities,
                 exploit_alert_triggered_by_attacker,
                 false_alarm_probability_by_attacker,
                 goal_conditions,
                 w=0.5):

        self.E = exploits_with_edges
        self.A = actions
        self.alerts = alert_keys
        self.__w = w
        self.__attacker_exploit_attempt_probabilities = attacker_exploit_attempt_probabilities
        self.__attacker_exploit_success_probabilities = attacker_exploit_success_probabilities
        self.__exploit_alert_triggered_by_attacker = exploit_alert_triggered_by_attacker
        self.__false_alarm_probability_by_attacker = false_alarm_probability_by_attacker
        self.__goal_conditions = goal_conditions
        self.T = False
        self.relevant_vertices_sets = self.calculate_relevant_vertices_set_unions()

    def calculate_relevant_vertices_set_unions(self):
        start = time.time()
        result = []
        relevant_vertices = []
        attack_graph_file = os.environ.get("TMP_GRAPH_FILE") or "tmp/attack_graph_received.json"

        with open(attack_graph_file, "r") as f:
            attack_graph_json = json.load(f)
            for table in attack_graph_json["payload"]["attack_graph"]["associations"]:
                vertex_set = {"AL-{0}".format(i) for i in set(table["relevant_vertices"]["AL"])}
                if vertex_set not in relevant_vertices:
                    relevant_vertices.append(vertex_set)

        for alert in self.A.values():
            if alert != []:
                vertex_set = set()
                for exploit in alert:
                    v_id = exploit.split("-")[1]
                    vertex_set.add("AL-{0}".format(v_id))
                if vertex_set not in relevant_vertices:
                    relevant_vertices.append(vertex_set)

        all_combinations = chain.from_iterable(combinations(relevant_vertices, r) for r in range(2))
        for combination in all_combinations:
            entry = set()
            for item in combination:
                entry = entry.union(item)
            entry = list(entry)
            entry.sort(key=lambda x: int(x.split("-")[1]))
            if entry not in result:
                result.append(entry)

        end = time.time()
        logging.debug("[TIMING] 'relevant_vertices' combinations calculation time: {0}".format(end - start))
        logging.debug("[GENERATOR] # of items: {0}\n".format(len(result)))
        return result

    def __heuristic(self, state):
        security_conditions_compromised = [].copy()
        for security_condition, is_compromised in state.items():
            if is_compromised == 1:
                security_conditions_compromised.append(security_condition)
        available_exploits = [].copy()
        for exploit, prepost in self.E.items():
            if set(prepost[0]).issubset(security_conditions_compromised) \
                    and not set(prepost[1]).issubset(security_conditions_compromised):
                available_exploits.append(exploit)
        s = 0
        if ('E-13' in available_exploits) or ('E-12' in available_exploits):
            s = 0

            if 'E-13' in available_exploits:
                s += 0.003

            if 'E-12' in available_exploits:
                s += 0.003
            return s

        return 0

    def __c_u(self, act, s):
        if self.T:
            self.T = False
            return 0

        if self.__c_s(s) > 1:
            self.T = True

        action = list(self.A[act])
        if action == []:
            return 0
        elif len(action) < 5:
            return 0.25
        elif len(action) in [5, 6, 7]:
            return 0.5
        elif len(action) == 12:
            return 1
        else:
            return 0.75

    def __c_s(self, state):
        s = 0
        for gc in self.__goal_conditions:
            if state[gc] == 1:
                s = 2
        return s

    def __cost(self, s, u):
        return self.__w * (self.__c_s(s) + self.__heuristic(s)) + (
                1 - self.__w) * self.__c_u(u, s)

    def __p_alert(self, exploit_j, alert, attackerType):
        return self.__exploit_alert_triggered_by_attacker[exploit_j][alert][attackerType]

    def get_p_alert(self, exploit_j, alert, attackerType):
        return self.__p_alert(exploit_j, alert, attackerType)

    def __p_attempt(self, attackerType, exploit_j):
        return self.__attacker_exploit_attempt_probabilities[attackerType][exploit_j]

    def __p_false_alarm(self, alert, attackerType):
        return self.__false_alarm_probability_by_attacker[alert][attackerType]

    def get_p_false_alarm(self, alert, attackerType):
        return self.__p_false_alarm(alert, attackerType)

    def __p_success(self, attackerType, exploit_j):
        return self.__attacker_exploit_success_probabilities[attackerType][exploit_j]

    @property
    def exploit_alert_triggered_by_attacker(self):
        return self.__exploit_alert_triggered_by_attacker.copy()

    def generate(self, state, attackerType, act, get_avail_exploits=False):
        compromised_threshold_default = 0.5
        compromised_threshold = os.environ.get("COMPROMISED_THRESHOLD") or None
        if compromised_threshold is not None:
            compromised_threshold = float(compromised_threshold)
            if (compromised_threshold < 0) and (compromised_threshold > 1):
                compromised_threshold = compromised_threshold_default
        else:
            compromised_threshold = compromised_threshold_default

        security_conditions_compromised = [].copy()
        for security_condition, is_compromised in state.items():
            if is_compromised >= compromised_threshold:
                security_conditions_compromised.append(security_condition)
        available_exploits = [].copy()
        for exploit, prepost in self.E.items():
            if set(prepost[0]).issubset(security_conditions_compromised) \
                    and not set(prepost[1]).issubset(security_conditions_compromised):
                available_exploits.append(exploit)

        blocked_exploits = self.A[act]
        attempted_exploits = [].copy()
        for i in available_exploits:
            a = 0
            if i in blocked_exploits:
                a = binomial(1, self.__p_attempt(attackerType, i)[1])
            else:
                a = binomial(1, self.__p_attempt(attackerType, i)[0])
            if a == 1:
                attempted_exploits.append(i)

        triggered_alerts = random.choice(self.relevant_vertices_sets)

        succesful_attempts = [].copy()
        for attempt in attempted_exploits:
            if attempt not in blocked_exploits:
                if binomial(1, self.__p_success(attackerType, attempt)):
                    succesful_attempts.append(attempt)

        next_state = state.copy()

        for succesful_attempt in succesful_attempts:
            for postcondition in self.E[succesful_attempt][1]:
                next_state[postcondition] = 1

        if get_avail_exploits:
            return next_state, attackerType, triggered_alerts, -self.__cost(state, act), available_exploits
        return next_state, attackerType, triggered_alerts, -self.__cost(state, act)

    def generate_simple(self, state, attackerType, act, observation, api_state, get_avail_exploits=False):
        compromised_threshold_default = 0.5
        compromised_threshold = os.environ.get("COMPROMISED_THRESHOLD") or None
        if compromised_threshold is not None:
            compromised_threshold = float(compromised_threshold)
            if (compromised_threshold < 0) and (compromised_threshold > 1):
                compromised_threshold = compromised_threshold_default
        else:
            compromised_threshold = compromised_threshold_default

        override_bus_choice = os.environ.get("GENERATOR_OVERRIDE_BUS_MSG") or None
        if (override_bus_choice is not None) and (override_bus_choice.lower() in "true"):
            override_bus_choice = True
        else:
            override_bus_choice = False

        if override_bus_choice:
            strict_policy = os.environ.get("GENERATOR_POLICY") or None
            if (strict_policy is not None) and (strict_policy.lower() in "strict"):
                strict_policy = True
            else:
                strict_policy = False
        else:
            if (api_state.get_tradeoff() >= 0) and (api_state.get_tradeoff() <= 1):
                if ((api_state.get_tradeoff() >= 0) and (api_state.get_tradeoff() < 0.25)) or (
                        (api_state.get_tradeoff() >= 0.5) and (api_state.get_tradeoff() < 0.75)):
                    strict_policy = True
                elif ((api_state.get_tradeoff() >= 0.25) and (api_state.get_tradeoff() < 0.5)) or (
                        (api_state.get_tradeoff() >= 0.75) and (api_state.get_tradeoff() <= 1)):
                    strict_policy = False
            else:
                strict_policy = True
                logging.debug("[GENERATOR] Invalid value for sa_tradeoff = {0}, setting policy to STRICT.".format(
                    api_state.get_tradeoff()))

        logging.debug("[GENERATOR] override_bus_choice = {0}".format(override_bus_choice))
        logging.debug("[GENERATOR] sa_tradeoff = {0}".format(api_state.get_tradeoff()))
        logging.debug("[GENERATOR] strict_policy = {0}".format(strict_policy))

        security_conditions_compromised = [].copy()
        for security_condition, is_compromised in state.items():
            if is_compromised >= compromised_threshold:
                security_conditions_compromised.append(security_condition)
        available_exploits = [].copy()
        for exploit, prepost in self.E.items():
            if set(prepost[0]).issubset(security_conditions_compromised) \
                    and not set(prepost[1]).issubset(security_conditions_compromised):
                available_exploits.append(exploit)

        blocked_exploits = self.A[act]

        converted_obs = set()
        for al in observation:
            id = al.split("-")[1]
            converted_obs.add("E-{0}".format(id))

        exploit_pool = set()
        for ex, _ in self.E.items():
            if ex not in blocked_exploits:
                exploit_pool.add(ex)

        if strict_policy:
            exploit_pool = exploit_pool.intersection(converted_obs)
        else:
            exploit_pool = exploit_pool.intersection(converted_obs)
            exploit_pool = exploit_pool.intersection(set(available_exploits))

        attempted_exploits = list(exploit_pool)

        succesful_attempts = [].copy()
        for attempt in attempted_exploits:
            if attempt not in blocked_exploits:
                if binomial(1, self.__p_success(attackerType, attempt)):
                    succesful_attempts.append(attempt)

        next_state = state.copy()

        for succesful_attempt in succesful_attempts:
            for postcondition in self.E[succesful_attempt][1]:
                next_state[postcondition] = 1

        if get_avail_exploits:
            return next_state, attackerType, -self.__cost(state, act), succesful_attempts, available_exploits
        return next_state, attackerType, -self.__cost(state, act), succesful_attempts
