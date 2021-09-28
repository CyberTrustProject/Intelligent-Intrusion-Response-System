from .node import Node


class Alert(Node):
    __triggered = False

    @property
    def node_type(self):
        return 'alert'

    def add_parent(self, node):
        assert node.node_type == 'exploit', 'node parameter is not of type Exploit: {0}'.format(node)

        super().add_parent(node)

    def add_child(self):
        raise NotImplementedError()

    def reset(self):
        self.__triggered = False

    @property
    def triggered(self):
        return self.__triggered

    @triggered.setter
    def triggered(self, value):
        assert isinstance(value, bool)
        self.__triggered = value
