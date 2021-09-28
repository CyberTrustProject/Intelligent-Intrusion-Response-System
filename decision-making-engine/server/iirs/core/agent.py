class Agent():
    gamma = None

    def __init__(self, gamma=0.95):
        if gamma >= 1:
            raise ValueError("gamma should be less than 1.")
        self.gamma = gamma
