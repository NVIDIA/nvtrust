import json

def validate_gpu_token_with_policy(token: str, auth_rules: str) -> bool:
    """Validate GPU token using a policy

    Args:
        token (str): EAT token
        auth_rules (str): policy

    Returns:
        bool: result
    """
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

def get_auth_rules(policy: str) -> str:
    """Extract Auth rule from the policy

    Args:
        policy (str): Policy

    Returns:
        str: Auth rules
    """
    if policy == "":
        return None
    policy_obj = json.loads(policy)
    return policy_obj['authorization-rules']