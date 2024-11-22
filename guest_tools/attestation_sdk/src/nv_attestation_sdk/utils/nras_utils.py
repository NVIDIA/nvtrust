#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
Utility functions for handling claims in a token for remote verifiers.
"""
from urllib.parse import urlparse
import base64
import logging
import json
import requests
import jwt

from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from ..utils import unified_eat_parser, claim_utils
from .. import attestation

console_logger = logging.getLogger("sdk-console")
file_logger = logging.getLogger("sdk-file")


def create_jwks_url(verifier_url: str) -> str:
    """Generate JWKS URL using the verifier URL

    Args:
        verifier_url (str): Verifier URL

    Returns:
        str: JWKS URL
    """
    parsed_url = urlparse(verifier_url)
    jwks_url = f"{parsed_url.scheme}://{parsed_url.netloc}/.well-known/jwks.json"
    return jwks_url


def validate_gpu_token(verifier, gpu_token: list, policy: str) -> bool:
    """Validate GPU token using a policy

    Args:
        verifier (_type_): verifier object
        gpu_token (str): EAT token
        policy (str): Appraisal policy for attestation results

    Returns:
        bool: result
    """
    file_logger.info("GPU token validation started with value %s:", gpu_token)
    if not (policy and gpu_token):
        file_logger.error("Invalid policy or token")
        return False
    return validate_gpu_token_with_policy(
        verifier[attestation.VerifierFields.URL],
        gpu_token,
        claim_utils.get_auth_rules(policy),
    )


def validate_claims_and_decode(
        verifier_url: str, auth_rules: dict, claim_type: str, claim_token: str
) -> bool:
    """
    A function that validates claims and decodes a claim token.
    """
    claims_decoded = decode_nras_token(verifier_url, claim_token)
    if not claim_utils.validate_claims(claims_decoded, auth_rules[claim_type]):
        file_logger.error("[ERROR] %s do not match the appraisal policy", claim_type)
        return False
    file_logger.info("%s have been validated successfully", claim_type)
    return True


def validate_gpu_token_with_policy(
        verifier_url: str, token: list, auth_rules: dict
) -> bool:
    """
    A function to validate a GPU token with a given policy.
    """
    if auth_rules["type"] != unified_eat_parser.get_overall_token_type(token):
        console_logger.error("[ERROR] Invalid token. Token type must be JWT. Found %s instead", unified_eat_parser.get_overall_token_type(token))
        return False

    if not validate_claims_and_decode(
            verifier_url,
            auth_rules,
            "overall-claims",
            unified_eat_parser.get_overall_claims_token(token),
    ):
        return False

    # check detached claims for all submodules
    detached_claims = unified_eat_parser.get_detached_claims_token(token)
    for key in detached_claims:
        file_logger.info(
            "Evaluating evidence for %s with appraisal policy for attestation results",
            key,
        )
        if not validate_claims_and_decode(
                verifier_url, auth_rules, "detached-claims", detached_claims[key]
        ):
            return False

    return True


def get_matching_key(jwks_data, kid):
    """
    A function that searches for a matching key based on the kid parameter
    in the provided jwks_data dictionary
    """
    for key in jwks_data["keys"]:
        if key["kid"] == kid:
            return key
    return None


def decode_jwt_token(token, cert):
    # Skipping verification of iat and nbf claims
    # until https://github.com/jpadilla/pyjwt/issues/814 is fixed
    """
    A function that decodes a JWT token using the provided certificate.
    """
    return jwt.decode(
        token,
        cert.public_key(),
        algorithms=["ES384"],
        options={"verify_iat": False, "verify_nbf": False},
    )


def decode_nras_token(verifier_url: str, token: str) -> dict:
    """
    A function to decode a token using the provided verifier URL and token.
    """
    try:
        jwks_url = create_jwks_url(verifier_url)
        console_logger.info("***** Validating Signature using JWKS endpoint %s ****** ", jwks_url)
        jwks_data = requests.get(jwks_url, timeout=30).json()
        kid = jwt.get_unverified_header(token)["kid"]
        matching_key = get_matching_key(jwks_data, kid)
        if matching_key and "x5c" in matching_key:
            try:
                matching_cert = matching_key["x5c"][0].encode()
                dercert = base64.b64decode(matching_cert)
                cert = load_der_x509_certificate(dercert, default_backend())
                decoded_token = decode_jwt_token(token, cert)
                file_logger.info("Decoded Token %s:", json.dumps(decoded_token, indent=2))
                console_logger.info("***** JWT token signature is valid. *****")
                return decoded_token
            except jwt.ExpiredSignatureError:
                console_logger.error("JWT token has expired.")
            except jwt.InvalidTokenError as e:
                console_logger.error("JWT token signature is invalid %s", repr(e))
        else:
            console_logger.error("No matching key or x5c key found for the provided kid.")
    except Exception as e:
        console_logger.error("Error in decoding token using JWKs endpoint %s", repr(e))
    return {}
