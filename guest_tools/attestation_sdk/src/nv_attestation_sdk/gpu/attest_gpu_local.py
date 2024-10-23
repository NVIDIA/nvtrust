#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import jwt
import logging
from ..utils.config import RIM_SERVICE_URL, OCSP_SERVICE_URL, ALLOW_HOLD_CERT

logger = logging.getLogger("sdk-console")

def get_evidence(nonce):

    """Generate GPU evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    from verifier import cc_admin

    gpu_evidence_list = cc_admin.collect_gpu_evidence_local(nonce)
    return gpu_evidence_list


def attest(nonce: str, gpu_evidence_list):
    """Attest a device locally

    Args:
        nonce (str): Nonce as hex string

    Returns:
        Attestation result and JWT token
    """
    attestation_result = False
    from verifier import cc_admin
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
        attestation_result, jwt_token = cc_admin.attest(params, nonce, gpu_evidence_list)
    except Exception as e:
        logger.error(f"\tException: {e}")
        jwt_token = get_err_eat_token()
    return attestation_result, jwt_token


def get_err_eat_token(errCode=1, errMsg="GPU_ATTESTATION_ERR"):
    errJson = {'x-nv-err-message': errMsg, 'x-nv-err-code': errCode}
    return jwt.encode(errJson,
                      'secret',
                      "HS256")
