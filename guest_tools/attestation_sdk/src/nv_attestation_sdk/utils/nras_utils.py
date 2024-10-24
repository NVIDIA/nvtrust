import requests
from cryptography.x509 import load_der_x509_certificate
import base64
import json
import jwt
from urllib.parse import urlparse
from ..utils import unified_eat_parser, claim_utils
from .. import attestation
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger("sdk-console")
debug_logger = logging.getLogger("sdk-file")


def create_jwks_url(verifier_url: str) -> str:
    """Generate JWKS URL using the verifier URL

    Args:
        verifier_url (str): Verifier URL

    Returns:
        str: JWKS URL
    """
    parsed_url = urlparse(verifier_url)
    jwks_url = parsed_url.scheme + "://" + parsed_url.netloc + "/" + ".well-known/jwks.json"
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
    debug_logger.info(f"validate_gpu_token invoked for gpu_token : {gpu_token}")
    if policy == "" or gpu_token == "":
        return False
    auth_rules = claim_utils.get_auth_rules(policy)
    return validate_gpu_token_with_policy(verifier[attestation.VerifierFields.URL], gpu_token, auth_rules)


def validate_gpu_token_with_policy(verifier_url: str, token: list, auth_rules: dict) -> bool:
    # check type
    if auth_rules["type"] != unified_eat_parser.get_overall_token_type(token):
        logger.error("\t[ERROR] Invalid token. Token type must be JWT")

    # check main claims
    overall_claims = unified_eat_parser.get_overall_claims_token(token)
    overall_claims_decoded = decode_nras_token(verifier_url, overall_claims)

    if not claim_utils.validate_claims(overall_claims_decoded, auth_rules["overall-claims"]):
        logger.error("\t[ERROR] Main claims does not match the appraisal policy")
        return False

    logger.info("overall claims validated successfully")

    # check detached claims for all submodules
    detached_claims = unified_eat_parser.get_detached_claims_token(token)
    for key in detached_claims:
        debug_logger.info(f"\tEvaluating evidence for {key} with appraisal policy for attestation results")
        detached_claims_decoded = decode_nras_token(verifier_url, detached_claims[key])
        if not claim_utils.validate_claims(detached_claims_decoded, auth_rules["detached-claims"]):
            logger.info("\t[ERROR] Submodules claims does not match the appraisal policy")
            return False

    logger.info("Detached claims validated successfully")
    return True


def decode_nras_token(verifier_url: str, token: str) -> dict:
    jwks_url = create_jwks_url(verifier_url)
    logger.info("***** Validating Signature using JWKS endpoint " + jwks_url + " ****** ")
    jwks_response = requests.get(jwks_url)
    jwks_data = jwks_response.json()
    header = jwt.get_unverified_header(token)
    kid = header['kid']
    # Find the key with the matching kid in the JWKS
    matching_key = None
    for key in jwks_data["keys"]:
        if key["kid"] == kid:
            matching_key = key
            break

    if matching_key and "x5c" in matching_key:
        try:
            matching_cert = matching_key["x5c"][0].encode()
            # Convert the base64-encoded X.509 certificate to a certificate object
            dercert = base64.b64decode(matching_cert)
            cert = load_der_x509_certificate(dercert, default_backend())
            # Verify the JWT token signature using the certificate's public key
            # skipping iat and nbf verification until https://github.com/jpadilla/pyjwt/issues/814 is fixed
            decoded_token = jwt.decode(
                token,
                cert.public_key(),
                algorithms=["ES384"],
                options={'verify_iat': False, 'verify_nbf': False}
            )
            json_formatted_str = json.dumps(decoded_token, indent=2)
            debug_logger.info(f"Decoded Token: {str(json_formatted_str)}")
            logger.info("***** JWT token signature is valid. *****")
            return decoded_token
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired.")
        except jwt.InvalidTokenError as e:
            logger.error("JWT token signature is invalid.", repr(e))
    else:
        logger.error("No matching key or x5c key found for the provided kid.")
    return {}
