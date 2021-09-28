from .node import Node

class Action(Node):

    @property
    def node_type(self):
        return 'action'

    def add_child(self, node):
        assert node.node_type == 'exploit'
        super().add_child(node)

    def add_parent(self):
        raise NotImplementedError()

    def perform(self):
        for _, ex in self.children.items():
            ex.blocked = True
        return
