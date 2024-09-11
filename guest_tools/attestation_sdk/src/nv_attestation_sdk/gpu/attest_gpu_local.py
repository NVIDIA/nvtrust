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
from ..utils.config import GPU_ARCH, OCSP_SERVICE_URL, RIM_SERVICE_URL, ALLOW_HOLD_CERT


def validate_gpu_token(verifier, gpu_token: str, policy: str):
    """Validate GPU token using a policy

    Args:
        verifier (_type_): verifier object
        gpu_token (str): EAT token
        policy (str): Appraisal policy for attestation results

    Returns:
        bool: result
    """
    if policy == "" or gpu_token == "":
        return False
    decoded_token = jwt.decode(gpu_token, algorithms='HS256', verify=False, key="secret")
    auth_rules = gpu_utils.get_auth_rules(policy)
    return gpu_utils.validate_gpu_token_with_policy(decoded_token, auth_rules)

def attest(nonce):
    """Attest a device locally

    Args:
        nonce (str): Nonce as hex string

    Returns:
        Attestation result and JWT token
    """
    attestation_result = False
    from verifier import cc_admin
    jwt_token = ""
    try:
        params = {"verbose": False,
                  "test_no_gpu": False,
                  "driver_rim": None,
                  "vbios_rim": None,
                  "user_mode": True,
                  'rim_root_cert': None,
                  'rim_service_url': RIM_SERVICE_URL,
                  'allow_hold_cert': ALLOW_HOLD_CERT,
                  'ocsp_url': OCSP_SERVICE_URL,
                  'nonce': nonce}
        attestation_result, jwt_token = cc_admin.attest(params)
    except Exception as e:
        print("\tException: ", e)
        jwt_token = get_err_eat_token()
    return attestation_result, jwt_token

def get_err_eat_token(errCode=1, errMsg="GPU_ATTESTATION_ERR"):
    errJson = {'x-nv-err-message': errMsg, 'x-nv-err-code': errCode}
    return jwt.encode(errJson,
                        'secret',
                        "HS256")

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

