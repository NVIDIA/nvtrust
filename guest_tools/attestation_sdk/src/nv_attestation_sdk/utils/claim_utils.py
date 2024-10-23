from typing import Any, Optional
import json
import logging
import jwt

file_logger = logging.getLogger("sdk-file")
console_logger = logging.getLogger("sdk-console")

def validate_claims(token: dict, auth_rules: dict) -> bool:
    file_logger.info(f"Comparing {token} with rules {auth_rules}")
    for key in auth_rules:
        if key in token:
            if token[key] != auth_rules[key]:
                console_logger.error(f"\tInvalid token. Authorized claims does not match the appraisal policy: {key}")
                return False
            else:
                file_logger.info(f"{auth_rules} has been validated")
        else:
            console_logger.error(f"\tInvalid token. Authorized claims is missing attribute: {key}")
            return False
    return True


def get_auth_rules(policy: str) -> Optional[Any]:
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


def decode_jwt(token, secret=None, algorithms=['HS256']):
    try:
        decoded_payload = jwt.decode(token, secret, algorithms=algorithms, options={"verify_signature": False})
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"