from ..core.agent import Agent
from timeit import default_timer as timer
from time import sleep
import time
from ..utils.helpers import powerset, UCB, find_the_key
from ..utils.older_history_tree import HistoryTree
from ..utils import helpers
from numpy.random import choice, binomial
from ..core.generator_for_agent import generator
from ..core.attack_graph import AttackGraph
import random
import matplotlib.pyplot as plt
import os
import logging

from ..envs.cns_toy_env_data import init_data

class POMCP(Agent):

    def __init__(self, attack_graph, attacker_types, generator = generator, gamma = 0.87, c = 3, \
    threshold = 0.0001, timeout = 500, no_particles = 1200, max_procs = 16):
        logging.debug("NEW AGENT !!!!!")
        self.output = {}
        self.output_counts = {}
        self.state_belief = []
        self.type_belief = []
        self.prior = []
        self.prior_type = []

        self.__attack_graph = attack_graph
        self.generator = generator
        self.e = threshold
        self.c = c
        self.no_process = max_procs
        self.timeout = int( timeout ) 
        self.no_particles = no_particles 
        self.init_state = {}
        leaf_nodes, leaf_execcode = init_data('leaf nodes')
        
        for k in attack_graph.security_conditions.keys():
            if k in leaf_nodes:
                if k in leaf_execcode:
                    self.init_state[k] = 0.5
                else:
                    self.init_state[k] = 1.0
            else:
                self.init_state[k] = 0.0

        logging.debug("[POMCP NEW] (Constructor) self.init_state = {0}".format(self.init_state))

        self.types = attacker_types
        self.actions = self.__attack_graph.actions
        self.actions_indices = list(self.actions.keys())
        self.exploits = self.__attack_graph.exploits
        self.exploits_indices = list(self.exploits.keys())
        self.alerts = self.__attack_graph.alerts
        self.alert_indices = self.alerts.keys()
        super(POMCP, self).__init__(gamma)
        self.tree = HistoryTree()

    def get_agents_belief(self) -> list:
        return ( choice(self.tree.nodes[-1][4]), choice(self.tree.nodes[-1][5]) )

    def __posterior_sample(self, Bh, Btype, action, observation):
        force_true = False
        sampling_timeout = int(os.environ.get("POSTERIOR_SAMPLE_TIMEOUT")) or 80
        if sampling_timeout <= 0:
            logging.warning("[POSTERIOR SAMPLE] Invalid value for 'sampling_timeout' (= {0}), default value used.".format(sampling_timeout))
            sampling_timeout = 80

        counter = 0
        start = time.time()
        while True:
            counter += 1
            if Bh == []:
                sampled_state_from_prior = self.init_state
            else:
                sampled_state_index = choice(range(len(Bh)))
                sampled_state_from_prior = Bh[sampled_state_index]
            if Btype == []:
                sampled_attacker_type_from_prior = choice(self.types)
            else:
                sampled_attacker_type_from_prior = choice(Btype)

            proposed_posterior_sample_state, proposed_posterior_sample_attacker_type, o_next, _ ,\
             available_exploits = self.generator.generate(sampled_state_from_prior, \
            sampled_attacker_type_from_prior, action, True)

            alerts_in_Zs = [].copy()
            for exploit in available_exploits:
                for alert in self.alert_indices:
                    if alert in self.generator.exploit_alert_triggered_by_attacker[exploit].keys():
                        if sampled_attacker_type_from_prior in \
                        self.generator.exploit_alert_triggered_by_attacker[exploit][alert].keys():
                            alerts_in_Zs += [alert]
            alerts_in_Zs = set(alerts_in_Zs)

            Condition = True
            for alert in alerts_in_Zs:
                if (alert in observation and alert not in o_next) or \
                (alert not in observation and alert in o_next):
                    Condition = False
                    break

            if Condition:
                num_positive_false_alarms = len([alert for alert in observation \
                if alert not in alerts_in_Zs])
                num_negative_false_alarms = len(self.alert_indices) - \
                len(alerts_in_Zs) - num_positive_false_alarms

                pfalse = self.generator.get_p_false_alarm(list(self.alert_indices)[0], sampled_attacker_type_from_prior)
                pfalsemax = None
                for i in self.types:
                    p_f_alarm = self.generator.get_p_false_alarm(list(self.alert_indices)[0], i)
                    dummy = p_f_alarm**num_positive_false_alarms * (1 - p_f_alarm)**num_negative_false_alarms
                    if pfalsemax is None or pfalsemax < dummy:
                        pfalsemax = dummy

                p_bar = pfalse**num_positive_false_alarms * (1 - pfalse)**num_negative_false_alarms
                p_accept = p_bar / pfalsemax 

                if binomial(1, p_accept) or force_true:
                    stop = time.time()
                    return proposed_posterior_sample_state, proposed_posterior_sample_attacker_type

                if counter > sampling_timeout:
                    force_true = True
                    logging.debug("[POSTERIOR SAMPLE] Forcing __posterior_sample to end at the next matched sample.")

    def update_belief(self, action, observation, Smoothing = False):
        obs = hash(str(observation))
        prior_belief = []
        prior_type_belief = []
        for dic in self.prior:
            action_node = dic[-1][1][action]
            observation_node = dic[action_node][1][obs] if obs in dic[action_node][1].keys() else None
            if observation_node is not None:
                prior_belief += dic[observation_node][4]
                prior_type_belief += dic[observation_node][5]        
        self.prior[:] = []
        if Smoothing:
            prior_type_belief = prior_type_belief + prior_type_belief + self.types
        
        self.tree.nodes[-1][4] = [].copy()
        self.tree.nodes[-1][5] = [].copy()
        for _ in range(self.no_particles):
            post_sample = self.__posterior_sample(prior_belief, prior_type_belief, action, observation)
            self.tree.nodes[-1][4].append(post_sample[0])
            self.tree.nodes[-1][5].append(post_sample[1])
        

    def respond(self):
        self.__search()
        ret = None
        max = None
        try:
            for k in self.output.keys():
                if self.output_counts[k] != 0:
                    aggregate = self.output[k]/self.output_counts[k]
                    if max is None or aggregate > max:
                        max = aggregate
                        ret = k
            
            self.output.clear()
            self.output_counts.clear()
        except Exception as e:
            logging.error(e)
            ret = "action1"
            logging.error("[POMCP NEW] ///////// erring /////////")

        assert ret is not None, 'Retry'
        return ret

    
    def __search_best(self, h):
        max_value = None
        best_action_node_key = None
        best_action = None
        if self.tree.nodes[h][4] != -1:
            children = self.tree.nodes[h][1]
            for action, child in children.items():
                if self.tree.nodes[child][2] == 0:
                    return action, child
                ucb = UCB(self.tree.nodes[h][2], self.tree.nodes[child][2], 
                self.tree.nodes[child][3], self.c)
                if max_value is None or max_value < ucb:
                    max_value = ucb
                    best_action_node_key = child
                    best_action = action
        return best_action, best_action_node_key


    def __search(self):
        Bh = self.tree.nodes[-1][4].copy()
        phi = self.tree.nodes[-1][5].copy()
        for _ in range(self.timeout):
            if Bh == []:
                sampled_state = self.init_state
            else:
                sampled_state_index = choice(range(len(Bh)))
                sampled_state = Bh[sampled_state_index]
            if phi == []:
                sampled_attacker_type = random.choice(self.types)
            else:
                sampled_attacker_type = choice(phi)
            self.__Simulate(sampled_state, sampled_attacker_type, -1, 0)
        children = self.tree.nodes[-1][1]

        for key, value in children.items():
            self.prior.append(self.tree.nodes)
            if key in self.output.keys():
                self.output[key] += self.tree.nodes[value][3]
                self.output_counts[key] += self.tree.nodes[value][2]
            else:
                self.output[key] = self.tree.nodes[value][3]
                self.output_counts[key] = self.tree.nodes[value][2]
            self.state_belief += self.tree.nodes[-1][4]
            self.type_belief += self.tree.nodes[-1][5]

        return 

    def __get_observation_node(self,h,sample_observation):
        sample_observation.sort(key=lambda x: int(x.split("-")[1]))
        ob = hash(str(sample_observation))
        if ob is None:
            raise ValueError("Observation is None")
        if ob not in list(self.tree.nodes[h][1].keys()):
            self.tree.ExpandTreeFrom(h, ob)
        Next_node = self.tree.nodes[h][1][ob]
        return Next_node

    def __rollout(self, s, phi, depth):
        if (self.gamma**depth < self.e or self.gamma == 0 ) and depth != 0:
            return 0


        action = choice(self.actions_indices)
        sample_state, _, _, r = self.generator.generate(s, phi, action) 
        cum_reward = r + self.gamma*self.__rollout(sample_state, phi, depth + 1)

        return cum_reward

    def __Simulate(self, s, φ, h, depth):
        if (self.gamma**depth < self.e or self.gamma == 0 ) and depth != 0:
            return 0

        if self.tree.isLeafNode(h):
            for action in self.actions:
                self.tree.ExpandTreeFrom(h, action, IsAction=True)
            new_value = self.__rollout(s, φ, depth)
            self.tree.nodes[h][2] += 1
            self.tree.nodes[h][3] = new_value
            self.tree.nodes[h][4] = [s]
            self.tree.nodes[h][5] = [φ]
            return new_value
        
    
        next_action, next_node = self.__search_best(h)
        sample_state, sample_type, sample_observation, reward = self.generator.generate(s, φ, next_action) 
        Next_node = self.__get_observation_node(next_node,sample_observation)
        
        cum_reward = reward + self.gamma*self.__Simulate(sample_state, sample_type, Next_node, depth + 1)
     
        self.tree.nodes[h][4].append(s)
        self.tree.nodes[h][5].append(φ)
        self.tree.nodes[h][2] += 1
        self.tree.nodes[next_node][2] += 1
        self.tree.nodes[next_node][3] += (cum_reward - self.tree.nodes[next_node][3])/self.tree.nodes[next_node][2]
        return cum_reward

    def __posterior_sample_simple(self, Bh, Btype, action, observation, api_state):
        while True:
            if Bh == []:
                sampled_state_from_prior = self.init_state
            else:
                sampled_state_index = choice(range(len(Bh)))
                sampled_state_from_prior = Bh[sampled_state_index]
            if Btype == []:
                sampled_attacker_type_from_prior = choice(self.types)
            else:
                sampled_attacker_type_from_prior = choice(Btype)

            proposed_posterior_sample_state, proposed_posterior_sample_attacker_type, _ , succesful_attempts, \
                available_exploits = self.generator.generate_simple(sampled_state_from_prior, sampled_attacker_type_from_prior, \
                    action, observation, api_state, True)

            alerts_in_Zs = [].copy()
            for exploit in available_exploits:
                for alert in self.alert_indices:
                    if alert in self.generator.exploit_alert_triggered_by_attacker[exploit].keys():
                        if sampled_attacker_type_from_prior in self.generator.exploit_alert_triggered_by_attacker[exploit][alert].keys():
                            alerts_in_Zs += [alert]
            alerts_in_Zs = set(alerts_in_Zs)

            num_positive_false_alarms = len([alert for alert in observation if alert not in alerts_in_Zs])
            num_negative_false_alarms = len(self.alert_indices) - len(alerts_in_Zs) - num_positive_false_alarms

            pfalse = self.generator.get_p_false_alarm(list(self.alert_indices)[0], sampled_attacker_type_from_prior)
            logging.debug("[DEBUG] pfalse = {0}".format(pfalse))
            pfalsemax = None
            for i in self.types:
                p_f_alarm = self.generator.get_p_false_alarm(list(self.alert_indices)[0], i)
                logging.debug("[DEBUG] p_f_alarm = {0}".format(p_f_alarm))
                dummy = p_f_alarm**num_positive_false_alarms * (1 - p_f_alarm)**num_negative_false_alarms
                logging.debug("[DEBUG] num_positive_false_alarms = {0}".format(num_positive_false_alarms))
                logging.debug("[DEBUG] num_negative_false_alarms = {0}".format(num_negative_false_alarms))
                logging.debug("[DEBUG] dummy = {0}".format(dummy))
                if pfalsemax is None or pfalsemax < dummy:
                    pfalsemax = dummy

            if pfalsemax == 0:
                pfalsemax = 0.00001

            p_bar = pfalse**num_positive_false_alarms * (1 - pfalse)**num_negative_false_alarms
            logging.debug("[DEBUG] p_bar = {0}".format(p_bar))
            logging.debug("[DEBUG] pfalsemax = {0}".format(pfalsemax))
            p_accept = p_bar / pfalsemax

            if binomial(1, p_accept):
                return proposed_posterior_sample_state, proposed_posterior_sample_attacker_type, succesful_attempts

    def update_belief_simple(self, action, observation, api_state):

        obs = hash(str(observation))
        prior_belief = []
        prior_type_belief = []
        for dic in self.prior:
            action_node = dic[-1][1][action]
            observation_node = dic[action_node][1][obs] if obs in dic[action_node][1].keys() else None
            if observation_node is not None:
                prior_belief += dic[observation_node][4]
                prior_type_belief += dic[observation_node][5]        
        self.prior[:] = []
        
        self.tree.nodes[-1][4] = [].copy()
        self.tree.nodes[-1][5] = [].copy()
        for _ in range(self.no_particles):
            proposed_posterior_sample_state, proposed_posterior_sample_attacker_type, succesful_attempts = self.__posterior_sample_simple(prior_belief, prior_type_belief, action, observation, api_state=api_state)
            self.tree.nodes[-1][4].append(proposed_posterior_sample_state)
            self.tree.nodes[-1][5].append(proposed_posterior_sample_attacker_type)
            return succesful_attempts

    def update_state_simple(self):
        Bh = self.tree.nodes[-1][4].copy()
        phi = self.tree.nodes[-1][5].copy()

        if Bh == []:
            sampled_state = self.init_state
        else:
            sampled_state_index = choice(range(len(Bh)))
            sampled_state = Bh[sampled_state_index]
        if phi == []:
            sampled_attacker_type = random.choice(self.types)
        else:
            sampled_attacker_type = choice(phi)
        self.__Simulate(sampled_state, sampled_attacker_type, -1, 0)
        children = self.tree.nodes[-1][1]

        for key, value in children.items():
            self.prior.append(self.tree.nodes)
            if key in self.output.keys():
                self.output[key] += self.tree.nodes[value][3]
                self.output_counts[key] += self.tree.nodes[value][2]
            else:
                self.output[key] = self.tree.nodes[value][3]
                self.output_counts[key] = self.tree.nodes[value][2]

            self.state_belief += self.tree.nodes[-1][4]
            self.type_belief += self.tree.nodes[-1][5]

        return 