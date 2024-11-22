#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
Utility functions for handling claims in a token for local verifiers.
"""
import logging
import jwt
from . import unified_eat_parser
from . import claim_utils


console_logger = logging.getLogger("sdk-console")
file_logger = logging.getLogger("sdk-file")


def validate_token(verifier: str, gpu_token: list, policy: str):
    """Validate token using a policy

    Args:
        gpu_token (str): EAT token
        policy (str): Appraisal policy for attestation results

    Returns:
        bool: result
    """
    if not (policy and gpu_token):
        console_logger.error("Invalid policy or token")
        return False
    return validate_token_with_policy(gpu_token, claim_utils.get_auth_rules(policy))


def validate_token_with_policy(token: list, auth_rules: dict) -> bool:
    """Validate token using a policy

    Args:
        token (str): EAT token
        auth_rules (str): policy

    Returns:
        bool: result
    """
    if auth_rules["type"] != unified_eat_parser.get_overall_token_type(token):
        console_logger.error("Invalid token type. Expected %s but received %s", auth_rules["type"], unified_eat_parser.get_overall_token_type(token))
        return False

    overall_claims = jwt.decode(
        unified_eat_parser.get_overall_claims_token(token),
        algorithms="HS256",
        verify=False,
        key="secret",
    )
    if not claim_utils.validate_claims(overall_claims, auth_rules["overall-claims"]):
        return False

    detached_claims = unified_eat_parser.get_detached_claims_token(token)
    for key, claim in detached_claims.items():
        if not claim_utils.validate_claims(
            jwt.decode(claim, algorithms="HS256", verify=False, key="secret"),
            auth_rules["detached-claims"],
        ):
            return False

    return True
