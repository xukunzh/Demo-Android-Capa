from typing import List, Dict, Set, Tuple, Union
from dataclasses import dataclass

from features import Feature, Address, FeatureSet

# The Result class here directly refers to the implementation of capa, which is used to save the result of rule matching
# Dataclass is used to make the code more concise, and success indicates whether the match is successful
@dataclass
class Result:
    success: bool
    statement: 'Statement'
    children: List['Result']
    locations: Set[Address] = None
    
    def __bool__(self):
        return self.success 

class Statement:
    def __init__(self, description=None):
        self.name = self.__class__.__name__
        self.description = description
    
    def __str__(self):
        return f"{self.name.lower()}()"
    
    def evaluate(self, features: FeatureSet):
        raise NotImplementedError()

class And(Statement):
    def __init__(self, children, description=None):
        super().__init__(description)
        self.children = children
    
    def evaluate(self, features: FeatureSet):
        results = []
        for child in self.children:
            result = child.evaluate(features)
            results.append(result)
            if not result:
                return Result(False, self, results)
        
        return Result(True, self, results)

class Or(Statement):
    def __init__(self, children, description=None):
        super().__init__(description)
        self.children = children
    
    def evaluate(self, features: FeatureSet):
        results = []
        for child in self.children:
            result = child.evaluate(features)
            results.append(result)
            if result:
                return Result(True, self, results)
        
        return Result(False, self, results)

class Not(Statement):
    def __init__(self, child, description=None):
        super().__init__(description)
        self.child = child
    
    def evaluate(self, features: FeatureSet):
        result = self.child.evaluate(features)
        return Result(not result, self, [result])

# FeatureNode class acts as a leaf node
class FeatureNode(Statement):
    def __init__(self, feature: Feature):
        super().__init__()
        self.feature = feature
    
    def __str__(self):
        return str(self.feature)
    
    def evaluate(self, features: FeatureSet):
        locs = features.get(self.feature, set())
        success = len(locs) > 0
        return Result(success, self, [], locs)
        
# The main entry for rule matching, using features to evaluate rule_statement
def match(rule_statement: Statement, features: FeatureSet, addr: Address) -> Tuple[FeatureSet, Dict[str, List[Tuple[Address, Result]]]]:
    results = {}
    
    result = rule_statement.evaluate(features)
    
    if result:
        rule_name = getattr(rule_statement, 'rule_name', 'unnamed_rule')
        results[rule_name] = [(addr, result)]
    
    return features, results