from .node import Node


class SecurityCondition(Node):
    __compromised = False
    __is_goal_condition = False

    @property
    def node_type(self):
        return 'security_condition'

    def add_parent(self, node):
        assert node.node_type == 'exploit', 'node sould be of type exploit: {0}'.format(node.node_type)
        super().add_parent(node)

    def add_child(self, node):
        assert node.node_type == 'exploit', 'node sould be of type exploit: {0}'.format(node.node_type)
        super().add_child(node)

    @property
    def compromised(self) -> bool:
        return self.__compromised

    @property
    def is_goal_condition(self):
        return self.__is_goal_condition

    @is_goal_condition.setter
    def is_goal_condition(self, value):
        assert isinstance(value, bool)
        self.__is_goal_condition = value

    @compromised.setter
    def compromised(self, value):
        assert isinstance(value, bool)
        self.__compromised = value

    def compromise(self):
        assert any(
            ex.has_succeeded for _, ex in self.parents.items()), 'no exploit leeding to this condition has succeeded'
        self.compromised = True
