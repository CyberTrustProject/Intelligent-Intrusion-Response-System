from .node import Node
from numpy.random import binomial
from .exploit_attempt_probability import ExploitAttemptProbability
from utils.helpers import is_probability


class Attacker(Node):
    __exploit_attempt_probabilities = None
    __exploit_success_probabilities = None
    __exploit_alert_trigger_probabilities = None

    @property
    def node_type(self):
        return 'attacker'

    def __init__(self, attacker_type):

        self.__exploit_attempt_probabilities = {}
        self.__exploit_success_probabilities = {}
        self.__exploit_alert_trigger_probabilities = {}
        super().__init__(attacker_type)

    def add_parent(self):
        raise NotImplementedError()

    def add_child(self,
                  node,
                  attempt_probability=(1, 1),
                  success_probability=1,
                  alert_trigger_probabilities={}):
        assert node.node_type == 'exploit'
        if not is_probability(attempt_probability[0]):
            raise ValueError('Not a valid probability: {0}'.format(
                attempt_probability[0]))
        if not is_probability(attempt_probability[1]):
            raise ValueError('Not a valid probability: {0}'.format(
                attempt_probability[1]))
        if not is_probability(success_probability):
            raise ValueError(
                'Not a valid probability: {0}'.format(success_probability))
        for val in alert_trigger_probabilities.values():
            if not is_probability(val):
                raise ValueError(
                    'Not a valid probability: {0}'.format(val))

        super().add_child(node)
        node.add_parent(self)

        self.__exploit_success_probabilities[node.key] = success_probability
        self.__exploit_attempt_probabilities[
            node.key] = ExploitAttemptProbability(attempt_probability[0],
                                                  attempt_probability[1])
        self.__exploit_alert_trigger_probabilities[node.
            key] = alert_trigger_probabilities

    def __attempt_exploit(self, exploit):
        attempt_probability = self.__exploit_attempt_probabilities[
            exploit.key].when(exploit.blocked)
        did_attempt = binomial(1, attempt_probability)
        triggered_alerts = []
        if did_attempt:
            for alert_key, prob in self.__exploit_alert_trigger_probabilities[exploit.key].items():
                was_triggered = binomial(1, prob)
                if was_triggered:
                    triggered_alerts.append(alert_key)
            exploit.set_was_attempted(triggered_alerts)
            if not exploit.blocked:
                if binomial(1, self.__exploit_success_probabilities[exploit.key]):
                    exploit.has_succeeded = True

    def attempt_available_exploits(self):
        gen = [ex for ex in self.children.values() if ex.available]
        for ex in gen:
            if ex.available:
                self.__attempt_exploit(ex)
