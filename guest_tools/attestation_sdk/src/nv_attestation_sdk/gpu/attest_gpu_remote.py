#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import json
import jwt
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from nv_attestation_sdk import attestation
from urllib.parse import urlparse
from nv_attestation_sdk.gpu import gpu_utils

from ..utils.config import REMOTE_VERIFIER_URL, GPU_ARCH


def attest(nonce: str, verifierUrl: str):
    """Attest a device using the remote Attestation URL

    Args:
        nonce (str): Nonce as hex string
        verifierUrl (str): Verifier URL

    Returns:
        Attestation result and JWT token
    """
    gpu_evidence_list = generate_evidence(nonce)
    return verify_evidence(nonce, gpu_evidence_list, verifierUrl)


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


def validate_gpu_token(verifier, gpu_token: str, policy: str) -> bool:
    """Validate GPU token using a policy

    Args:
        verifier (_type_): verifier object
        gpu_token (str): EAT token
        policy (str): Appraisal policy for attestation results

    Returns:
        bool: result
    """
    verifier_url = verifier[attestation.VerifierFields.URL]
    jwks_url = create_jwks_url(verifier_url)
    print("***** Validating Signature using JWKS endpont " + jwks_url + " ****** ")
    jwks_response = requests.get(jwks_url)
    jwks_data = jwks_response.json()
    header = jwt.get_unverified_header(gpu_token)
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
            cert_bytes = b"".join([b"-----BEGIN CERTIFICATE-----\n",
                                   matching_key["x5c"][1].encode(),
                                   b"\n-----END CERTIFICATE-----\n"])
            dercert = base64.b64decode(matching_cert)
            cert = load_der_x509_certificate(dercert, default_backend())
            # Get the public key in PEM format
            public_key_pem = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # Verify the JWT token signature using the certificate's public key
            # skipping iat and nbf verification until https://github.com/jpadilla/pyjwt/issues/814 is fixed
            decoded_token = jwt.decode(
                gpu_token,
                cert.public_key(),
                algorithms=["ES384"],
                options={'verify_iat': False, 'verify_nbf': False}
            )
            json_formatted_str = json.dumps(decoded_token, indent=2)
            print("Decoded Token ", str(json_formatted_str))
            print("***** JWT token signature is valid. *****")
            auth_rules = gpu_utils.get_auth_rules(policy)
            return gpu_utils.validate_gpu_token_with_policy(decoded_token, auth_rules)
        except jwt.ExpiredSignatureError:
            print("JWT token has expired.")
        except jwt.InvalidTokenError as e:
            print("JWT token signature is invalid.", repr(e))
    else:
        print("No matching key or x5c key found for the provided kid.")
    return False


def generate_evidence(nonce=""):
    """Generate GPU evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    print("generate_evidence")
    from verifier import cc_admin
    gpu_evidence_list = cc_admin.collect_gpu_evidence(nonce)
    return gpu_evidence_list


def verify_evidence(nonce: str, gpu_evidence_list, verifier_url):
    """Verify GPU evidence with the Remote Verifier

    Args:
        nonce (_type_): Nonce represented as hex string
        gpu_evidence_list (_type_): GPU Evidence list
        verifierUrl (str, optional): Verifier URL. Defaults to "https://nras.attestation.nvidia.com/v1/attest/gpu".

    Returns:
        _type_: _description_
    """
    if not verifier_url:
        verifier_url = REMOTE_VERIFIER_URL

    attestation_result = False
    jwt_token = ""
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        for i, gpu_evidence in enumerate(gpu_evidence_list):
            gpu_evidence = gpu_evidence_list[i]
            current_gpu_status = False
            payload = build_payload(nonce, gpu_evidence['attestationReportHexStr'],
                                    gpu_evidence['certChainBase64Encoded'])
            print("Calling NRAS to attest GPU evidence...")
            response = requests.request("POST", verifier_url, headers=headers, data=payload)
            reponse_json = response.json()
            if response.status_code == 200:
                print("**** Attestation Successful ****")
                jwt_token = reponse_json["eat"]
                print("Entity Attestation Token is " + jwt_token)
                current_gpu_status = True
            else:
                print("**** Attestation Failed ****")
                print("received NRAS response: ", reponse_json)
                #jwt_token = get_err_eat_token(reponse_json['errorCode'], reponse_json['message'])
            if i == 0:
                attestation_result = current_gpu_status
            else:
                attestation_result = overall_status and current_gpu_status
    except Exception as e:
        print("\tException: ", e)
    return attestation_result, jwt_token


def build_payload(nonce, evidence, cert_chain):
    data = dict()
    data['nonce'] = nonce
    encoded_evidence_bytes = evidence.encode("ascii")
    encoded_evidence = base64.b64encode(encoded_evidence_bytes)
    encoded_evidence = encoded_evidence.decode('utf-8')
    data['evidence'] = encoded_evidence
    data['arch'] = GPU_ARCH
    data['certificate'] = str(cert_chain)
    payload = json.dumps(data)
    return payload
