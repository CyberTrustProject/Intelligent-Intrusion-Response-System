import uuid


class Node:
    __parents = None
    __children = None

    def __init__(self, key=uuid.uuid4()):
        self.__key = key
        self.parents = {}
        self.children = {}

    @property
    def key(self) -> str:
        return self.__key

    @property
    def node_type(self) -> str:
        return 'generic'

    @property
    def parents(self):
        return self.__parents

    @parents.setter
    def parents(self, value):
        assert isinstance(value, dict), 'parents should be a dictionary: {0}'.format(value)
        self.__parents = value

    def add_parent(self, node):
        assert isinstance(node, Node), 'the parent of Node should be a Node: {0}'.format(node)
        self.parents[node.key] = node

    def has_parent(self, key) -> bool:
        return key in self.parents.keys()

    def remove_parent(self, key):
        assert self.has_parent(key), 'cannot remove parent, key not found: {0}'.format(key)
        del self.parents[key]

    @property
    def children(self):
        return self.__children

    @children.setter
    def children(self, value):
        assert isinstance(value, dict), 'children should be a dictionary: {0}'.format(value)
        self.__children = value

    def add_child(self, node):
        assert isinstance(node, Node)
        self.__children[node.key] = node

    def has_child(self, key):
        return key in self.children.keys()

    def remove_child(self, key):
        assert self.has_child(key), 'cannot remove child, key not found: {0}'.format(key)
        del self.__children[key]
