from . import claim_utils
import logging
from . import unified_eat_parser
import jwt
console_logger = logging.getLogger("sdk-console")
debug_logger = logging.getLogger("sdk-file")


def validate_token(gpu_token: list, policy: str):
    """Validate token token using a policy

    Args:
        gpu_token (str): EAT token
        policy (str): Appraisal policy for attestation results

    Returns:
        bool: result
    """
    if policy == "" or gpu_token == "":
        return False
    # decoded_token = jwt.decode(gpu_token, algorithms='HS256', verify=False, key="secret")
    auth_rules = claim_utils.get_auth_rules(policy)
    return validate_token_with_policy(gpu_token, auth_rules)


def validate_token_with_policy(token: list, auth_rules: dict) -> bool:
    """Validate token using a policy

    Args:
        token (str): EAT token
        auth_rules (str): policy

    Returns:
        bool: result
    """
    # check type
    if auth_rules["type"] != unified_eat_parser.get_overall_token_type(token):
        console_logger.error("Invalid token. Token type must be JWT")

    # check main claims
    overall_claims = unified_eat_parser.get_overall_claims_token(token)
    overall_claims_decoded = jwt.decode(overall_claims, algorithms='HS256', verify=False, key="secret")
    if not claim_utils.validate_claims(overall_claims_decoded, auth_rules["overall-claims"]):
        return False

    # check detached claims for all submodules
    detached_claims = unified_eat_parser.get_detached_claims_token(token)

    for key in detached_claims:
        debug_logger.info(f"Evaluating evidence for {key} with appraisal policy for attestation results")
        detached_claims_decoded = jwt.decode(detached_claims[key], algorithms='HS256', verify=False, key="secret")
        eval_result = claim_utils.validate_claims(detached_claims_decoded, auth_rules["detached-claims"])
        if not eval_result:
            console_logger.info(f"Appraisal policy does not match with Attestation results for {key}")
            return False
        else:
            console_logger.info(f"Appraisal policy applied successfully to Attestation results for {key}")

    return True