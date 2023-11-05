import json

def validate_gpu_token_with_policy(token: str, auth_rules: str):
    for key in auth_rules:
        if key in token:
            if type(auth_rules[key]) is dict:
                return validate_gpu_token_with_policy(token[key], auth_rules[key])
            else:
                if token[key] != auth_rules[key]:
                    print("\t[ERROR] Invalid token. Authorized claims does not match the appraisal policy: ", key)
                    return False
        else:
            print("\t[ERROR] Invalid token. Authorized claims does not match the appraisal policy: ", key)
            return False
    return True

def get_auth_rules(policy: str):
    if policy == "":
        return None
    policy_obj = json.loads(policy)
    return policy_obj['authorization-rules']