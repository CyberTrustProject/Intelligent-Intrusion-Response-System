import numpy as np

class Agent:
    def allowlearn(self):
        self.learn = 1

    def preventlearn(self):
        self.learn = 0

    def train(self, n_episodes):
        if self.verbosity: print('Training...')
        self.allowlearn()
        return self.runEpisodes(n_episodes) / n_episodes

    def benchmark(self, n_episodes):
        if self.verbosity: print('benchmarking...')
        self.preventlearn()
        return self.runEpisodes(n_episodes) / n_episodes

    def runEpisodes(self, n_episodes):
        accumulatedReward = 0
        for episode_i in range(n_episodes):
            if self.verbosity: print('Episode ' + str(episode_i))
            accumulatedReward += self.episode()
        return accumulatedReward


class EGreedyPolicyTabular:
    def __init__(self, epsilon, decay=1):
        self.epsilon = epsilon
        self.decay = decay

    def getAction(self, Q, state):

        if np.random.random() > self.epsilon:
            return self.greedyAction(Q, state)
        else:
            return self.randomAction(Q)

    def randomAction(self, Q):
        nA = Q[0].shape[0]
        return np.random.randint(nA)

    def greedyAction(self, Q, state):
        nA = Q[0].shape[0]
        maxima_index = []
        maxVal = None

        for action in range(nA):
            value = Q[state][action]
            if maxVal == None: 
                maxVal = value
            if value > maxVal: 
                maxima_index = [action]
                maxVal = value
            elif value == maxVal: 
                maxima_index.append(action)

        return np.random.choice(maxima_index)

    def epsilonDecay(self):
        self.epsilon *= self.decay

    def episodeUpdate(self):
        self.epsilonDecay()


class EGreedyPolicyVFA:
    def __init__(self, epsilon, decay=1):
        self.epsilon = epsilon
        self.decay = decay

    def setNActions(self, nA):
        self.nA = nA

    def getAction(self, VFA, featurize, state):
        if np.random.random() > self.epsilon:
            return self.greedyAction(VFA, featurize, state)
        else:
            return self.randomAction()

    def randomAction(self):
        return np.random.randint(self.nA)

    def greedyAction(self, VFA, featurize, state):
        maxima_index = []
        maxVal = None 

        for action in range(self.nA):
            features = featurize.featureStateAction(state, action)
            value = VFA.getValue(features)

            if maxVal is None:
                maxVal = value
            if value > maxVal: 
                maxima_index = [action]
                maxVal = value
            elif value == maxVal:
                maxima_index.append(action)

        return np.random.choice(maxima_index)

    def getDetArray(self, VFA, featurize, nS):
        detActions = np.zeros((nS, 1))
        actionVals = np.zeros((self.nA, 1)) 
        for state in range(nS):
            for action in range(self.nA):
                features = featurize.featureStateAction(state, action)
                actionVals[action] = VFA.getValue(features)
            detActions[state] = np.argmax(actionVals) 
        return detActions

    def epsilonDecay(self):
        self.epsilon *= self.decay

    def episodeUpdate(self):
        self.epsilonDecay()


class SoftmaxPolicyVFA:
    def __init__(self, tau=1):
        self.tau = tau

    def setUpWeights(self, dimensions, value=1):
        self.weights = np.ones(dimensions) * value

    def setNActions(self, nA):
        self.nA = nA

    def getAction(self, featurize, state):
        probabilities = self.computeWeights(featurize, state)

        return np.random.choice(range(self.nA), p=probabilities)

    def greedyAction(self, featurize, state):
        probabilities = self.computeWeights(VFA, featurize, state)

        return np.argmax(probabilities)

    def computeWeights(self, featurize, state):
        values = np.zeros((self.nA, 1))
        for action in range(self.nA):
            feature = featurize.featureStateAction(state, action)
            values[action] = np.dot(feature.T, self.weights)

        values_exp = np.exp(values / self.tau - max(values))
        probabilities = (values_exp / sum(values_exp)).flatten()
        return probabilities

    def getGradient(self, featurize, state, action):
        features = featurize.featureStateAction(state, 0) 
        for a in range(1, self.nA): features = np.hstack([features, featurize.featureStateAction(state, a)])
        mean_feature = np.mean(features, 1).reshape(-1, 1) 
        gradient = (features[:, action].reshape(-1, 1) - mean_feature) / self.tau 
        return gradient

    def updateWeightsDelta(self, delta):
        self.weights += delta


class Featurize():
    def set_nSnA(self, nS, nA):
        self.nS = nS
        self.nA = nA

    def featureState(self, state):
        return featureTableState(state, self.nS)

    def featureStateAction(self, state, action):
        return featureTableStateAction(state, action, self.nS, self.nA)



def featureTableState(state, nS):
    feature = np.zeros((nS, 1))
    feature[state] = 1
    return feature


def featureTableStateAction(state, action, nS, nA):
    feature = np.zeros((nS * nA, 1))
    feature[state * nA + action] = 1
    return feature


class LinearVFA:
    def setUpWeights(self, dimensions, value=1):
        self.weights = np.ones(dimensions) * value

    def returnWeights(self, dimensions, value=1):
        return np.ones(dimensions) * value

    def getValue(self, features):
        return np.dot(features.T, self.weights)

    def getGradient(self, features):
        return features

    def updateWeightsDelta(self, delta_weight):
        self.weights += delta_weight

    def updateWeightsMatrix(self, A, b):
        self.weights = np.matmul(np.linalg.inv(A), b)

    def getWeights(self):
        return self.weights

    def setWeights(self, weights):
        self.weights = weights


class TableLookupModel:
    def __init__(self, nS, nA):
        self.nS = nS
        self.nA = nA
        self.N = np.zeros((nS, nA))
        self.SprimeCounter = np.zeros((nS, nA, nS))
        self.Rcounter = np.zeros((nS, nA))
        self.observedStates = []
        self.observedActions = [[] for i in range(nS)]
        self.terminalStates = []

    def addExperience(self, experience):
        s, a, r, s_prime = experience
        self.N[s][a] += 1
        self.SprimeCounter[s][a][s_prime] += 1
        self.Rcounter[s][a] += r
        if not s in self.observedStates: self.observedStates.append(s)
        if not a in self.observedActions[s]: self.observedActions[s].append(a)

    def sampleStatePrime(self, state, action):
        if self.N[state][action] == 0: return np.random.choice(range(self.nS))

        prob = self.SprimeCounter[state][action] / self.N[state][action]
        return np.random.choice(range(self.nS), p=prob)

    def sampleReward(self, state, action):
        if self.N[state][action] == 0: return 0

        return self.Rcounter[state][action] / self.N[state][action]

    def sampleRandState(self):
        return np.random.choice(self.observedStates)

    def sampleRandAction(self, state):
        return np.random.choice(self.observedActions[state])

    def addTerminalStates(self, term_states):
        self.terminalStates = term_states

    def isTerminal(self, state):
        return state in self.terminalStates
