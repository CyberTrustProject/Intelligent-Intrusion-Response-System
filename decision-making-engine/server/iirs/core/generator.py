from numpy.random import binomial
import logging


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

    def __c_u(self, act):
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
                s = 1
        return s

    def __cost(self, s, u):
        return self.__w * (self.__c_s(s)) + (
                1 - self.__w) * self.__c_u(u)

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
        return self.__attacker_exploit_success_probabilities[attackerType][
            exploit_j]

    @property
    def exploit_alert_triggered_by_attacker(self):
        return self.__exploit_alert_triggered_by_attacker.copy()

    def generate(self, state, attackerType, act, get_avail_exploits=False):
        security_conditions_compromised = [].copy()
        for security_condition, is_compromised in state.items():
            if is_compromised == 1:
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

        triggered_alerts = [].copy()

        for exploit in attempted_exploits:
            for alert in self.alerts:
                if alert in self.__exploit_alert_triggered_by_attacker[exploit].keys() and \
                        attackerType in self.__exploit_alert_triggered_by_attacker[exploit][alert].keys():
                    if binomial(1, self.get_p_alert(exploit, alert, attackerType)):
                        triggered_alerts.append(alert)
        triggered_alerts = list(set(triggered_alerts))

        for exploit in self.E.keys():
            if exploit not in attempted_exploits:
                for alert in self.alerts:
                    if alert in self.__exploit_alert_triggered_by_attacker[exploit].keys() and \
                            attackerType in self.__exploit_alert_triggered_by_attacker[exploit][alert].keys():
                        if binomial(1, self.get_p_false_alarm(alert, attackerType)):
                            triggered_alerts.append(alert)
        triggered_alerts = sorted(list(set(triggered_alerts)))

        succesful_attempts = [].copy()
        for attempt in attempted_exploits:
            if attempt not in blocked_exploits:
                if binomial(1, self.__p_success(attackerType, attempt)):
                    succesful_attempts.append(attempt)

        next_state = state.copy()
        for succesful_attempt in succesful_attempts:
            for postcondition in self.E[succesful_attempt][1]:
                next_state[postcondition] = 1
        logging.debug("[DEBUG] Instantaneous cost: {0}".format(-self.__cost(state, act)))
        if get_avail_exploits:
            return next_state, attackerType, triggered_alerts, -self.__cost(
                state, act), available_exploits

        return next_state, attackerType, triggered_alerts, -self.__cost(
            state, act)
