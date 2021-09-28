import sys
sys.path.append("..")
from core.attack_graph import AttackGraph
from core.attacker import Attacker
import numpy as np
import copy
from utils.history_tree import HistoryTree
from utils.helpers import UCB
from numpy.random import binomial, choice
from core.generator import generator
from .cns_toy_env_data import init_data
import logging

class CyberNetSecToyEnv():
  __attack_graph = None
  __attacker = None
  __step = {}

  def __init__(self, renderer):
    attacker_keys, alert_keys, real_attacker, \
        goal_conditions, exploit_with_edges, \
            action_blocks_exploit, exploit_alert_triggered_by_attacker,\
                  false_alarm_probability_by_attacker, \
                      p_attacker_attempts_exploit,\
                          p_attacker_succeeds_exploit, _, _ = init_data()
    self.__ids_mapping_info=0
    self.metadata = {'render.modes': ['human']}
    self.__attack_graph = AttackGraph(
      goal_conditions,
      exploit_with_edges, 
      action_blocks_exploit,
      exploit_alert_triggered_by_attacker,
      false_alarm_probability_by_attacker, 
      renderer)

    A = {
      k: v.children.keys()
      for k, v in self.__attack_graph.actions.items()
    }

    G = generator(
      A,
      exploit_with_edges,
      list(alert_keys.values()),
      p_attacker_attempts_exploit,
      p_attacker_succeeds_exploit,
      exploit_alert_triggered_by_attacker,
      false_alarm_probability_by_attacker,
      goal_conditions,
      w=0.5
    )

    exploit_attacker_triggers_alert = {}
    for ex in self.__attack_graph.exploits.values(): 
      exploit_ = ex.key
      if exploit_ not in exploit_attacker_triggers_alert.keys():
        exploit_attacker_triggers_alert[exploit_] = {}
      for at_type in attacker_keys.values():
        if at_type not in exploit_attacker_triggers_alert[exploit_].keys():
          exploit_attacker_triggers_alert[exploit_][at_type] = {}

        for alerts in self.__attack_graph.alerts.values():
          alert_ = alerts.key
          if alert_ in exploit_alert_triggered_by_attacker[exploit_].keys() and \
          at_type in exploit_alert_triggered_by_attacker[exploit_][alert_].keys():
            exploit_attacker_triggers_alert[exploit_][at_type][alert_] = exploit_alert_triggered_by_attacker[exploit_][alert_][at_type]
                
    self.real_attacker = real_attacker
    
    self.__attacker = Attacker(self.real_attacker)  
    for ex in self.__attack_graph.exploits.values():
      attempt = p_attacker_attempts_exploit[self.real_attacker][ex.key]
      success = p_attacker_succeeds_exploit[self.real_attacker][ex.key]
      trigger = exploit_attacker_triggers_alert[ex.key][self.real_attacker]
      self.__attacker.add_child(ex, attempt, success, trigger)

    self.time = 0
    self.cum_cost = 0
    self.__generator = G

    self.seed()
    self.reset()

  def step(self, action):
    self.time += 1
    self.__attack_graph.reset()

    state = {
        k: int(v.compromised)
        for k, v in self.__attack_graph.security_conditions.items()
    }
    
    self.__attack_graph.actions[action].perform()

    self.__attacker.attempt_available_exploits()
    self.__attack_graph.trigger_false_alarms(self.real_attacker)

    state2 = {
        k: int(v.compromised)
        for k, v in self.__attack_graph.security_conditions.items()
    }
    logging.debug("[CNS TOY ENV] True State: {0}\n".format(state2))

    attempted = [exploit.key for exploit in self.__attack_graph.exploits.values() if exploit.attempted]
    logging.debug("[CNS TOY ENV] Attempted Exploits: {0}\n".format(attempted))
    
    triggered_alerts = self.__attack_graph.triggered_alerts.keys()
    logging.debug("[CNS TOY ENV] Triggered Alerts: {0}\n".format(triggered_alerts))
    
    _, _, _, cost = self.__generator.generate(state, self.__attacker.key, action)
    self.cum_cost -= cost * 0.9**self.time
    done = all(sc.compromised for sc in self.__attack_graph.goal_conditions)

    return triggered_alerts, self.cum_cost , done, None

  def reset(self):
    self.cum_cost = 0
    self.time = 0 
    self.__attack_graph.reset()
    return [], 0, False, copy.deepcopy(self.__attack_graph)

  def render(self, mode='human', belief_state = None, alerts = None, plot = None, close=False):
    if mode == 'human':
      self.__attack_graph.render(belief_state = belief_state, plot = plot, alerts = alerts)
    else:
      raise ValueError("mode render invalid")

  def seed(self, seed=None):
    return

  @property
  def attack_graph(self):
    return self.__attack_graph
  
  @property
  def ids_mapping_info(self):
    return self.__ids_mapping_info

  def close(self):
    return
