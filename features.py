from typing import Set, Dict, Any

class Feature:
    """
    Feature base class, all detectable feature types inherit from here
    It is necessary to ensure that the feature is hashable,
    because it is used as a dictionary key
    """
    def __init__(self, value):
        self.value = value
    
    def __hash__(self):
        return hash((self.__class__.__name__, self.value))
    
    def __eq__(self, other):
        return (
            isinstance(other, self.__class__) and
            self.value == other.value
        )
    
    def __str__(self):
        return f"{self.__class__.__name__}({self.value})"

class API(Feature):
    """API call feature"""
    pass

class String(Feature):
    """String feature"""
    pass

class Address:
    def __init__(self, method):
        self.method = method
    
    def __str__(self):
        return self.method

FeatureSet = Dict[Feature, Set[Address]]