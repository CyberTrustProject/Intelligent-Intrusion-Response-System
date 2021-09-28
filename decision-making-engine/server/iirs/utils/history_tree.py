from multiprocessing import Lock


class HistoryTree():
    def __init__(self, giveParameters=['isRoot', {}, 0, 0, [],
                                       []], shared_dictionary=None, Value=None):
        self.obs_lock = Lock()
        self.Lock = Lock()
        if Value is None:
            self.count = -1
        else:
            self.count = Value
        if shared_dictionary is None:
            self.nodes = {}
        else:
            self.nodes = shared_dictionary

        self.giveParameters = []

        for i in giveParameters:
            if type(i) == str or type(i) == int:
                self.giveParameters.append(i)
            else:
                self.giveParameters.append(i.copy())
        self.nodes[self.count.value] = self.giveParameters

    def ExpandTreeFrom(self, parent, index, IsAction=False):
        with self.Lock:
            self.count.increment()
            if IsAction:
                self.nodes[self.count.value] = [parent, {}, 0, 0, -1, []]
                y = self.nodes[parent]
                z = y[1]
                z[index] = self.count.value
                y[1] = z
                self.nodes[parent] = y
            else:
                self.nodes[self.count.value] = [parent, {}, 0, 0, [], []]
                y = self.nodes[parent]
                z = y[1]
                z[index] = self.count.value
                y[1] = z
                self.nodes[parent] = y

    def isLeafNode(self, n):
        if self.nodes[n][2] == 0:
            return True
        else:
            return False

    def getObservationNode(self, h, sample_observation):
        with self.obs_lock:
            if sample_observation not in list(self.nodes[h][1].keys()):
                self.ExpandTreeFrom(h, sample_observation)
            Next_node = self.nodes[h][1][sample_observation]
        return Next_node

    def prune(self, node):
        children = self.nodes[node][1].copy()
        del self.nodes[node]
        for _, child in children.items():
            self.prune(child)

    def make_new_root(self, new_root):
        self.nodes[-1] = self.nodes[new_root].copy()

        del self.nodes[new_root]

        y = self.nodes[-1]
        y[0] = 'isRoot'
        self.nodes[-1] = y
        for _, child in self.nodes[-1][1].items():
            y = self.nodes[child]
            y[0] = -1
            self.nodes[child] = y

    def prune_after_action(self, action, observation):
        action_node = self.nodes[-1][1][action]

        new_root = self.getObservationNode(action_node, observation)

        if self.nodes[new_root][4] == []:
            parent = self.nodes[new_root][0]
            prev_parent = self.nodes[parent][0]
            y = self.nodes[new_root]
            y[4] = self.nodes[prev_parent][4].copy()
            self.nodes[new_root] = y
            y = self.nodes[new_root]
            y[5] = self.nodes[prev_parent][5].copy()
            self.nodes[new_root] = y
        y = self.nodes[action_node]
        z = y[1]
        del z[observation]
        y[1] = z
        self.nodes[action_node] = y
        self.prune(-1)
        self.make_new_root(new_root)
