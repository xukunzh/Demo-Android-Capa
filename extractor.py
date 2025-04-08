import json
import subprocess
import time
import os
from typing import List, Tuple, Generator

from features import Feature, API, String, Address, FeatureSet

class AndroidFeatureExtractor:
    """
    This class implements dynamic feature extraction of Android applications. 
    It has not yet inherited the FeatureExtractor of capa.
    The core function is to start Frida to monitor Android applications 
    and collect API call information as features.
    """
    def __init__(self, package_name, frida_script_path):
        self.package_name = package_name
        self.frida_script_path = frida_script_path
        self.features = {}  # Feature -> set(Address)
        self.reported_features = set()  # Already reported features
        self.debug_mode = False  # Controls whether to print detailed debug info
    
    def start_monitoring(self):
        """Start Frida monitoring"""
        if not os.path.exists(self.frida_script_path):
            print(f"Error: Frida script file does not exist: {self.frida_script_path}")
            return
        
        cmd = [
            "frida",
            "-U",
            "-l", self.frida_script_path,
            "-f", self.package_name
        ]
        
        print(f"Executing command: {' '.join(cmd)}")
        
        # Start the Frida subprocess and set up a pipeline to get output
        self.process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1  # Line buffering for real-time output
        )
        
        print(f"Starting to monitor application: {self.package_name}")
        
        # Start error output monitoring thread
        import threading
        def monitor_stderr():
            while True:
                error_line = self.process.stderr.readline()
                if not error_line:
                    break
                print(f"Frida error: {error_line.strip()}")
        
        # Separate thread to handle Frida error output
        stderr_thread = threading.Thread(target=monitor_stderr)
        stderr_thread.daemon = True
        stderr_thread.start()
        
        self._collect_features()
    
    def _collect_features(self):
        """Collect features from Frida output"""
        while True:
            line = self.process.stdout.readline()
            if not line:
                print("Frida process output ended")
                break
                
            # Print all output for debugging
            print(f"Frida output: {line.strip()}")
                
            # Try to parse JSON data
            if "{" in line and "}" in line:
                try:
                    start = line.find("{")
                    end = line.rfind("}") + 1
                    json_str = line[start:end]
                    
                    data = json.loads(json_str)
                    
                    if "type" in data and data["type"] == "api":
                        feature = API(data["name"])

                        method = data.get("method", "unknown")
                        
                        if "args" in data and isinstance(data["args"], dict):
                            args_str = ",".join(f"{k}={v}" for k, v in data["args"].items())
                            method = f"{method}({args_str})"
                        
                        address = Address(method)
                        
                        feature_id = f"{feature.value}@{address.method}"
                        
                        # Only report new features
                        if feature_id not in self.reported_features:
                            self.reported_features.add(feature_id)
                            print(f"Detected API call: {feature.value} at {address}")
                        
                        if feature not in self.features:
                            self.features[feature] = set()
                        
                        self.features[feature].add(address)
                        
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    print(f"Error processing output: {e}")
    
    def stop_monitoring(self):
        """Stop Frida monitoring"""
        if hasattr(self, 'process'):
            self.process.terminate()
            print("Stopping monitoring")
            
            # Wait for process to terminate
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                print("Forcibly terminated Frida process")
    
    def get_features(self) -> FeatureSet:
        """Get collected feature set"""
        # Only print detailed info in debug mode
        if self.debug_mode:
            print(f"Current number of collected features: {len(self.features)}")
            for feature, addresses in self.features.items():
                print(f"  - {feature}: {len(addresses)} locations")
        else:
            total_addresses = sum(len(addresses) for addresses in self.features.values())
            print(f"Features collected: {len(self.features)} unique features, {total_addresses} locations", end="\r")
        
        return self.features
    
    def print_statistics(self):
        """Print statistics about detected API calls"""
        print("\n=== API Call Statistics ===")
        
        total_features = len(self.features)
        total_locations = sum(len(locs) for locs in self.features.values())
        print(f"Total unique API calls: {total_features}")
        print(f"Total API call instances: {total_locations}")
        
        if total_features > 0:
            print("\nTop API calls by frequency:")
            sorted_apis = sorted(
                [(feature, len(locs)) for feature, locs in self.features.items()],
                key=lambda x: x[1],
                reverse=True
            )
            
            # Print top 5 or all if less than 5
            for i, (feature, count) in enumerate(sorted_apis[:5]):
                print(f"{i+1}. {feature.value}: {count} calls")
        
        print("===========================")