from graphviz import Digraph
import multiprocessing
from .sockets.server import ServerProcess
import json
import logging


class Renderer(object):
    def render(self, close=False):
        raise NotImplementedError('this method should be overwritten by the subclasses')


class NoopRenderer(Renderer):
    def render(self, attack_graph, close=False):
        pass


class AttackGraphTextRenderer(Renderer):
    def render(self, attack_graph, close=False):
        print(attack_graph)


class GraphvizRenderer(Renderer):

    def construct_state_graph(self, attack_graph):
        exploits = attack_graph.exploits
        dot = Digraph(comment='Attack Graph')
        dot.attr(bgcolor="transparent")
        dot.attr(size="5.0,7.0")
        atta_type = attack_graph.attacker_type
        dot.node(atta_type, shape='square', style='filled', fillcolor="/orrd9/{0}".format(9))
        for exploit in exploits.values():
            preconditions = exploit.preconditions
            postconditions = exploit.postconditions
            labels = []
            exploitcolor = 'black'
            if exploit.blocked:
                exploitcolor = 'green'
            if exploit.attempted:
                exploitcolor = 'orange'
            if exploit.attempted and exploit.blocked:
                exploitcolor = 'blue'
            dot.node(exploit.key, fontcolor='white', shape='pentagon', style='filled', fillcolor=exploitcolor,
                     penwidth="3")
            exploitcolor1 = 'black'
            penwidth1 = '3'
            style1 = "filled"
            if exploit.attempted:
                style1 = "dashed"

            for postcondition in postconditions.values():
                nodecolor = 'black'
                if postcondition.compromised:
                    nodecolor = 'red'
                if postcondition.key not in labels:
                    if postcondition.key not in ["SC-11", "SC-12"]:
                        dot.node(postcondition.key, style='filled', \
                                 fontcolor='white', shape='circle', fillcolor=nodecolor, penwidth='3')
                    else:
                        dot.node(postcondition.key, style='filled', \
                                 fontcolor='white', shape='doublecircle', fillcolor=nodecolor, penwidth='3')
                    labels.append(postcondition.key)
                dot.edge(exploit.key, postcondition.key, penwidth='3')

            for precondition in preconditions.values():
                if precondition.key not in labels:
                    nodecolor = 'black'
                    if precondition.compromised:
                        nodecolor = 'red'
                    dot.node(precondition.key, fontcolor='white', shape='circle', style='filled', fillcolor=nodecolor,
                             penwidth='3')
                    labels.append(precondition.key)

                dot.edge(precondition.key, exploit.key, style=style1, color=exploitcolor1, penwidth=penwidth1)

        return dot

    def construct_belief_graph(self, attack_graph, belief_state_and_attacker):

        color_A = 1
        max_beliefA = None
        belief_state = None
        belief_attacker = None
        if belief_state_and_attacker is not None:
            belief_state = belief_state_and_attacker[0]
            belief_attacker = belief_state_and_attacker[1]
            for k in belief_attacker.keys():
                if max_beliefA is None or max_beliefA < belief_attacker[k]:
                    max_beliefA = belief_attacker[k]

        exploits = attack_graph.exploits
        dot = Digraph(comment='Attack Graph')
        dot.attr(bgcolor="transparent")
        dot.attr(size="5.0,7.0")
        penwidth1 = '3'
        max_belief = None

        if belief_attacker is not None:
            for i in belief_attacker.keys():
                if max_beliefA is not None and max_beliefA != 0:
                    color_A = int(9 * (belief_attacker[i] / max_beliefA))
                    if color_A == 0:
                        color_A = 1
                dot.node(i, fontcolor='white', shape='square', style='filled', \
                         fillcolor="/orrd9/{0}".format(color_A), penwidth="3")

        if belief_state is not None:
            for k in belief_state.keys():
                if max_belief is None or max_belief < belief_state[k]:
                    max_belief = belief_state[k]
        for exploit in exploits.values():
            preconditions = exploit.preconditions
            postconditions = exploit.postconditions
            labels = []
            dot.node(exploit.key, fontcolor='white', shape='pentagon', style='filled', fillcolor="black",
                     penwidth="3")

            for postcondition in postconditions.values():
                if postcondition.key not in labels:
                    color_ = 1

                    if postcondition.key not in ["SC-11", "SC-12"]:
                        if belief_state is not None and max_belief != 0:
                            color_ = int(4 * (belief_state[postcondition.key] / max_belief)) + 4
                            if belief_state[postcondition.key] == 0:
                                color_ = 1
                        dot.node(postcondition.key, style='filled', \
                                 fontcolor='white', shape='circle', \
                                 fillcolor="/orrd9/{0}".format(color_), \
                                 penwidth='3')
                    else:
                        dot.node(postcondition.key, style='filled', \
                                 fontcolor='white', shape='doublecircle', fillcolor="/orrd9/{0}".format(color_),
                                 penwidth='3')
                    labels.append(postcondition.key)
                dot.edge(exploit.key, postcondition.key, penwidth='3')

            for precondition in preconditions.values():
                color_ = 1
                if precondition.key not in labels:
                    if belief_state is not None and max_belief != 0:
                        color_ = int(4 * (belief_state[precondition.key] / max_belief)) + 4
                        if belief_state[precondition.key] == 0:
                            color_ = 1
                        dot.node(precondition.key, fontcolor='white', shape='circle', style='filled', \
                                 fillcolor="/orrd9/{0}".format(color_), penwidth='3')
                    labels.append(precondition.key)

                dot.edge(precondition.key, exploit.key, style='filled', color="black", penwidth=penwidth1)

        return dot

    def render(self, attack_graph, close=False):
        dot = self.construct_state_graph(attack_graph)
        dot.render(filename='Attack Graph', format='svg', view=True)


manager = multiprocessing.Manager()
message_queue = manager.Queue()


class SocketRenderer(GraphvizRenderer):
    def __init__(self, sem):
        sp = ServerProcess(message_queue, sem)
        sp.daemon = True
        sp.start()

    def render(self, attack_graph, belief_state, plot, alerts):
        state = self.construct_state_graph(attack_graph)
        logging.debug("[RENDER] Constructed state visualize")
        belief = self.construct_belief_graph(attack_graph, belief_state)
        logging.debug("[RENDER] Constructed belief visualize")
        message = {
            'state': state.pipe(format='svg').decode('utf-8'),
            'belief': belief.pipe(format='svg').decode('utf-8'),
            'plot': plot,
            'alerts': alerts
        }
        message_queue.put(json.dumps(message))
        logging.debug("viz message sent")

    def close_server(self):
        message_queue.put(json.dumps('1234'))
