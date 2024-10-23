#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import logging
from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin

from ..utils.config import RIM_SERVICE_URL, OCSP_SERVICE_URL, ALLOW_HOLD_CERT

logger = logging.getLogger("sdk-console")


def attest(nonce: str, evidence_list):
    """Attest a device locally

    Args:
        evidence_list:
        nonce (str): Nonce as hex string

    Returns:
        Attestation result and JWT token
    """
    attestation_result = False
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
        attestation_result, jwt_token = nvswitch_admin.attest(params, nonce, evidence_list)
    except Exception as e:
        logger.error(f"\tException: {e}")
    return attestation_result, jwt_token
