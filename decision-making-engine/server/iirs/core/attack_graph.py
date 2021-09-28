from itertools import chain, combinations
from .exploit import Exploit
from .security_condition import SecurityCondition
from .action import Action
from .renderer import NoopRenderer
from .alert import Alert
from numpy.random import binomial
from envs.cns_toy_env_data import init_data
from iirs.utils.helpers import getAllactions
import logging


class AttackGraph():

    def __init__(self,
                 goal_conditions=[],
                 exploits_with_edges={},
                 action_blocks_exploit={},
                 exploit_alert_triggered_by_attacker={},
                 false_alarm_probability_by_attacker={},
                 renderer=NoopRenderer()):
        self.leaf_nodes, self.leaf_execcode = init_data(leaf='leaf_nodes')
        self.__security_conditions = {}
        self.__exploits = {}
        self.__actions = {}
        self.__alerts = {}
        self.__blocked_exploits = []
        self.__goal_conditions = []
        self.__initialize_exploits_and_conditions(exploits_with_edges)
        self.__initialize_actions(action_blocks_exploit)
        self.__initialize_alerts(exploit_alert_triggered_by_attacker)
        self.__false_alarms_prob_by_attacker = false_alarm_probability_by_attacker
        self.__renderer = renderer
        self.__goal_conditions = [sc for sc_key, sc in self.__security_conditions.items() if sc_key in goal_conditions]

        for sc in self.__goal_conditions:
            sc.is_goal_condition = True

        self.reset_security_conditions_state()

    def reset_security_conditions_state(self):
        for k, sc in self.__security_conditions.items():
            if k in self.leaf_nodes:
                sc.compromised = True

    def __initialize_actions(self, action_blocks_exploit):
        actions = self.__calculate_all_action_combinations(action_blocks_exploit).copy()
        logging.debug('[DEBUG] attack_graph.py __initialize_actions actions')
        logging.debug(actions)

        for key, value in actions.items():
            if not value:
                if not self.has_action(key):
                    action = Action(key)
                    self.add_action(action)

            for exploit_key in value:
                if not self.has_exploit(exploit_key):
                    raise LookupError(
                        'could not find exploit with key {0} in the attack graph'
                            .format(exploit_key))
                else:
                    if self.has_action(key):
                        self.actions[key].add_child(self.exploits[exploit_key])
                    else:
                        action = Action(key)
                        action.add_child(self.exploits[exploit_key])
                        self.add_action(action)

    def __initialize_exploits_and_conditions(self, exploits_with_edges):
        for exploit_key, precondition_postcondition_tuple in exploits_with_edges.items():

            exploit = Exploit(exploit_key)
            self.add_exploit(exploit)

            for precondition_key in precondition_postcondition_tuple[0]:
                security_precondition = None
                if not self.has_security_condition(precondition_key):
                    security_precondition = SecurityCondition(precondition_key)
                    self.add_security_condition(security_precondition)
                else:
                    security_precondition = self.security_conditions[
                        precondition_key]
                security_precondition.add_child(exploit)
                exploit.add_parent(security_precondition)

            for postcondition_key in precondition_postcondition_tuple[1]:

                if not self.has_security_condition(postcondition_key):
                    security_postcondition = SecurityCondition(
                        postcondition_key)
                    self.add_security_condition(security_postcondition)
                else:
                    security_postcondition = self.security_conditions[
                        postcondition_key]
                security_postcondition.add_parent(exploit)
                exploit.add_child(security_postcondition)

    def __initialize_alerts(self, exploit_alert_triggered_by_attacker):
        for exploit_key, alert_attacker in exploit_alert_triggered_by_attacker.items(
        ):
            for alert_key, _ in alert_attacker.items():
                if not self.has_exploit(exploit_key):
                    raise LookupError(
                        'could not find exploit with key {0} in the attack graph'
                            .format(exploit_key))
                else:
                    if self.has_alert(alert_key):
                        self.alerts[alert_key].add_parent(self.exploits[exploit_key])
                        self.exploits[exploit_key].add_child(self.alerts[alert_key])
                    else:
                        alert = Alert(alert_key)
                        alert.add_parent(self.exploits[exploit_key])
                        self.exploits[exploit_key].add_child(alert)
                        self.add_alert(alert)

    def __powerset(self, iterable):
        s = list(iterable)
        return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))

    def __actions_linear(self, iterable):
        s = list(iterable)
        return chain.from_iterable(combinations(s, r) for r in range(2))

    def __calculate_all_action_combinations(self, actions):
        return getAllactions(actions)

    def has_security_condition(self, key):
        return key in self.__security_conditions.keys()

    def add_security_condition(self, node):
        assert isinstance(node, SecurityCondition)
        if self.has_security_condition(node.key):
            raise IndexError('security condition with key {0} already exists'.format(node.key))
        self.__security_conditions[node.key] = node

    @property
    def security_conditions(self):
        return self.__security_conditions

    @property
    def compromised_security_conditions(self):
        return {
            k: v
            for k, v in self.security_conditions.items()
            if v.compromised
        }

    @property
    def goal_conditions(self):
        return self.__goal_conditions

    def has_exploit(self, key):
        return key in self.__exploits.keys()

    def add_exploit(self, node):
        assert isinstance(node, Exploit)
        if self.has_exploit(node.key):
            raise IndexError('exploit with key {0} already exists'.format(node.key))
        self.__exploits[node.key] = node

    @property
    def exploits(self):
        return self.__exploits

    def has_action(self, key):
        return key in self.__actions.keys()

    def add_action(self, node):
        assert isinstance(node, Action)
        if self.has_action(node.key):
            raise IndexError('action with key {0} already exists'.format(node.key))
        self.__actions[node.key] = node

    @property
    def actions(self):
        return self.__actions

    def block_exploit(self, key):
        if not self.has_exploit(key):
            raise KeyError(
                'could not find exploit with key {0} in the attack graph'.
                    format(key))
        if key in self.__blocked_exploits:
            raise KeyError(
                'exploit with key {0} is already blocked'.format(key))
        self.__exploits[key].blocked = True
        self.__blocked_exploits.append(key)

    def is_exploit_blocked(self, key):
        return key in self.__blocked_exploits

    def add_alert(self, node):
        assert isinstance(node, Alert)
        if self.has_alert(node.key):
            raise IndexError('alert with key {0} already exists'.format(
                node.key))
        self.__alerts[node.key] = node

    @property
    def alerts(self):
        return self.__alerts

    def has_alert(self, key):
        return key in self.alerts.keys()

    @property
    def triggered_alerts(self):
        return {
            k: v
            for k, v in self.alerts.items()
            if v.triggered
        }

    def trigger_false_alarms(self, attype):
        for alert_key, alert in self.alerts.items():
            probability = self.__false_alarms_prob_by_attacker[alert_key][attype]
            if not alert.triggered:
                if binomial(1, probability):
                    alert.triggered = True

    @property
    def attacker_type(self):
        exp = list(self.exploits.values())[0]
        for child in exp.parents.values():
            if child.node_type == "attacker":
                return child.key

    def reset(self):
        for ex in self.exploits.values():
            ex.reset()

        for al in self.alerts.values():
            al.reset()

    def render(self, belief_state, plot, alerts):
        self.__renderer.render(self, belief_state=belief_state, plot=plot, alerts=alerts)
