import numpy as np
from itertools import chain, combinations


def is_probability(value):
    if type(value) == float or type(value) == int:
        return (value >= 0) and (value <= 1)
    if type(value) == list:
        return (np.sum(value) == 1) and (all(val >= 0 for val in value)) and (all(val <= 1 for val in value))


def find_the_key(alerts, dictionary):
    for key, value in dictionary.items():
        if value == alerts:
            return key


def UCB(N, n, V, c=1):
    return V + c * np.sqrt(np.log(N) / n)


def powerset(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))


def actions_linear(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(2))


def extract_belief_from_particles(Bh):
    no_particles = len(Bh)
    frequency_count = None
    for state in Bh:
        if frequency_count is None:
            frequency_count = state.copy()
        else:
            for key in frequency_count.keys():
                frequency_count[key] += state[key]
    for key in frequency_count.keys():
        frequency_count[key] = frequency_count[key] / no_particles
    return frequency_count


def extract_attack_belief(Ba):
    ans = {}
    for i in set(Ba):
        ans[i] = Ba.count(i) / len(Ba)
    return ans


def getAllactions(actions):

    Actions = {}
    ACT = actions_linear([actions[key] for key in actions.keys()])

    i = 1
    for a in ACT:
        action_name = 'action{0}'.format(i)
        if len(a) == 0:
            Actions[action_name] = []
        else:
            Actions[action_name] = a[0]
        i += 1

    return Actions
