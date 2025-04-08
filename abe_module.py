import json
import os

# Define access policy for a file
def define_policy(file_path, policy_dict):
    policy_file = file_path + ".policy.json"
    with open(policy_file, 'w') as f:
        json.dump(policy_dict, f)
    print(f"Policy set for file: {policy_file}")

# Check if user attributes satisfy policy
def check_access(user_attrs, file_path):
    policy_file = file_path + ".policy.json"
    if not os.path.exists(policy_file):
        print("No policy file found.")
        return False

    with open(policy_file, 'r') as f:
        policy = json.load(f)

    for key, value in policy.items():
        if key not in user_attrs or user_attrs[key] != value:
            return False
    return True
