#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
Utility functions for handling claims in a token.
"""
from typing import Any, Optional
import json
import logging
import jwt

file_logger = logging.getLogger("sdk-file")
console_logger = logging.getLogger("sdk-console")


def validate_claims(token: dict, auth_rules: dict) -> bool:
    """
    A function to validate the claims in a token based on the provided authorization rules.

    Parameters:
    - token (dict): The token containing the claims to be validated.
    - auth_rules (dict): The authorization rules to compare the token claims against.

    Returns:
    - bool: True if all token claims match the authorization rules, False otherwise.
    """
    file_logger.info("Comparing token: %s with rules auth_rules: %s", token, auth_rules)
    for key in auth_rules:
        if key in token:
            if token[key] != auth_rules[key]:
                console_logger.error(
                    "[ERROR] Invalid token. Authorized claims does not match "
                    "the appraisal policy: %s",
                    key,
                )
                return False
            else:
                console_logger.info("%s has been validated", auth_rules)
        else:
            console_logger.error(
                "[ERROR] Invalid token. Authorized claims is missing attribute: %s", key
            )
            return False
    return True


def get_auth_rules(policy: str) -> Optional[Any]:
    """Extract Auth rule from the policy

    Args:
        policy (str): Policy

    Returns:
        str: Auth rules
    """
    if not policy:
        console_logger.error("Policy is empty")
        return None
    return json.loads(policy)["authorization-rules"]


def decode_jwt(token, secret=None, algorithms=None):
    """
    A function to decode a JWT token using the provided secret key and algorithms.

    Parameters:
    token (str): The JWT token to decode.
    secret (str): The secret key used to decode the token. Defaults to None.
    algorithms (list): The list of algorithms to use for decoding. Defaults to ["HS256"].

    Returns:
    dict or str: The decoded payload if successful, otherwise returns a string indicating the issue.
    """
    if algorithms is None:
        algorithms = ["HS256"]
    try:
        decoded_payload = jwt.decode(
            token, secret, algorithms=algorithms, options={"verify_signature": False}
        )
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"
