class HistoryTree():
    def __init__(self, giveParameters=['isRoot', {}, 0, 0, [], []]):
        self.count = -1
        self.nodes = {}

        self.giveParameters = []

        for i in giveParameters:
            if type(i) == str or type(i) == int:
                self.giveParameters.append(i)
            else:
                self.giveParameters.append(i.copy())
        self.nodes[self.count] = self.giveParameters

    def ExpandTreeFrom(self, parent, index, IsAction=False):
        self.count += 1
        if IsAction:
            self.nodes[self.count] = [parent, {}, 0, 0, -1, []]
            self.nodes[parent][1][index] = self.count
        else:
            self.nodes[self.count] = [parent, {}, 0, 0, [], []]
            self.nodes[parent][1][index] = self.count

    def isLeafNode(self, n):
        if self.nodes[n][2] == 0:
            return True
        else:
            return False

    def getObservationNode(self, h, sample_observation):
        if sample_observation not in list(self.nodes[h][1].keys()):
            self.ExpandTreeFrom(h, sample_observation)
        Next_node = self.nodes[h][1][sample_observation]
        return Next_node

    def prune(self, node):
        children = self.nodes[node][1]
        del self.nodes[node]
        for _, child in children.items():
            self.prune(child)

    def make_new_root(self, new_root):
        self.nodes[-1] = self.nodes[new_root].copy()

        del self.nodes[new_root]

        self.nodes[-1][0] = 'isRoot'
        for _, child in self.nodes[-1][1].items():
            self.nodes[child][0] = -1

    def prune_after_action(self, action, observation):
        action_node = self.nodes[-1][1][action]
        new_root = self.getObservationNode(action_node, observation)

        if self.nodes[new_root][4] == []:
            parent = self.nodes[new_root][0]
            prev_parent = self.nodes[parent][0]
            self.nodes[new_root][4] = self.nodes[prev_parent][4].copy()
            self.nodes[new_root][5] = self.nodes[prev_parent][5].copy()

        del self.nodes[action_node][1][observation]

        self.prune(-1)

        self.make_new_root(new_root)
