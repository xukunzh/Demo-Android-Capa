import os
import sys
import yaml
import time
import argparse
from typing import Dict

from features import API, String, Address
from engine import And, Or, Not, FeatureNode, match
from extractor import AndroidFeatureExtractor

def load_rule(rule_path):
    """
    Load the YAML rule file and parse it into a Statement object

    The rule format refers to the YAML format of capa, which has two parts: meta and features
    """
    with open(rule_path, 'r') as f:
        rule_data = yaml.safe_load(f)
    
    rule_name = rule_data['rule']['meta']['name']
    features = rule_data['rule']['features']
    
    statement = parse_statement(features[0])
    statement.rule_name = rule_name
    
    return rule_name, statement

def parse_statement(statement_data):
    """
    Recursively parse YAML rules into Statement objects

    Build an abstract syntax tree to represent the rule logic
    """
    if 'and' in statement_data:
        children = [parse_statement(s) for s in statement_data['and']]
        return And(children)
    elif 'or' in statement_data:
        children = [parse_statement(s) for s in statement_data['or']]
        return Or(children)
    elif 'not' in statement_data:
        child = parse_statement(statement_data['not'])
        return Not(child)
    elif 'api' in statement_data:
        return FeatureNode(API(statement_data['api']))
    elif 'string' in statement_data:
        return FeatureNode(String(statement_data['string']))
    else:
        raise ValueError(f"Unknown statement type: {statement_data}")

def main():
    parser = argparse.ArgumentParser(description="Mini-Capa Android Analyzer")
    parser.add_argument("package_name", help="Android application package name to analyze")
    parser.add_argument("-r", "--rules", default="rules", help="Rules directory")
    args = parser.parse_args()
    
    # Load all rule files from the rule directory
    rules = {}
    rules_dir = args.rules
    for rule_file in os.listdir(rules_dir):
        if rule_file.endswith('.yml'):
            rule_path = os.path.join(rules_dir, rule_file)
            rule_name, statement = load_rule(rule_path)
            rules[rule_name] = statement
    
    print(f"Loaded {len(rules)} rules")
    
    # Create a feature extractor and specify the Frida script
    frida_script = os.path.join("frida_scripts", "monitor_file_ops.js")
    extractor = AndroidFeatureExtractor(args.package_name, frida_script)

    reported_results = set()
    
    # Track feature counts from last processing to detect new features
    last_feature_counts = {}

    try:
        extractor.start_monitoring()
        
        while True:
            time.sleep(1)
            
            # Get currently collected features
            features = extractor.get_features()

            current_feature_counts = {}
            for feature, addresses in features.items():
                current_feature_counts[feature] = len(addresses)
            
            has_new_features = False
            for feature, count in current_feature_counts.items():
                if feature not in last_feature_counts or count > last_feature_counts[feature]:
                    has_new_features = True
                    break
            
            # Skip rule matching if no new features
            if not has_new_features:
                last_feature_counts = current_feature_counts.copy()
                continue
                
            last_feature_counts = current_feature_counts.copy()
            
            # Evaluate all rules
            app_address = Address("application")
            for rule_name, statement in rules.items():
                _, results = match(statement, features, app_address)
                
                # Only show newly matched results
                if rule_name in results:
                    for addr, result in results[rule_name]:
                        # Create unique identifier for each result
                        result_id = f"{rule_name}:{addr}"
                        
                        if result_id not in reported_results:
                            reported_results.add(result_id)
                            print(f"\n[+] Detected capability: {rule_name}")
                            print(f"    - Triggered at {addr}")
    
    except KeyboardInterrupt:
        print("\nUser interrupted monitoring")
    finally:
        extractor.stop_monitoring()
        extractor.print_statistics()
    
    print("\nAnalysis complete")

if __name__ == "__main__":
    main()