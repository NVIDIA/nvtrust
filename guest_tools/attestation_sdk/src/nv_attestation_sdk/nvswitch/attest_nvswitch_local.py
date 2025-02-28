#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module is responsible for local attestation of Nvswitch using nvswitch-verifier.
"""
import logging
import jwt
from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin
from ..utils.config import RIM_SERVICE_URL, OCSP_SERVICE_URL
from ..utils.config import get_allow_hold_cert
from nv_attestation_sdk.utils.logging_config import get_logger

logger = get_logger()


def get_evidence(nonce, options):
    """
    A function that fetches evidence for NvSwitch to perform local attestation.

    Parameters:
    nonce (str): The nonce value for fetching evidence.

    Returns:
    list: A list of evidence for NvSwitch.
    """
    try:
        ppcie_mode = options.get("ppcie_mode")

        logger.debug("Fetching evidence for NvSwitch to perform local attestation")
        switch_evidence_list = nvswitch_admin.collect_evidence(nonce, ppcie_mode=ppcie_mode)
        logger.debug("Evidence list for NvSwitch %s", switch_evidence_list)
        return switch_evidence_list
    except Exception as e:
        logger.error("Error in collecting evidences for switches: %s", e)
    return []


def attest(nonce: str, evidence_list, attestation_options):
    """Attest a device locally

    Args:
        evidence_list:
        nonce (str): Nonce as hex string
        attestation_options (dict): Arguments with which to perform attestation 

    Returns:
        Attestation result and JWT token
    """
    attestation_result = False
    jwt_token = ""
    try:
        params = {
            "verbose": False,
            "test_no_gpu": False,
            "driver_rim": None,
            "vbios_rim": None,
            "user_mode": True,
            "rim_root_cert": None,
            "rim_service_url": attestation_options.get("rim_service_url") or RIM_SERVICE_URL,
            "allow_hold_cert": get_allow_hold_cert(),
            "ocsp_url": attestation_options.get("ocsp_url") or OCSP_SERVICE_URL,
            "nonce": nonce,
            'ocsp_nonce_disabled': attestation_options.get("ocsp_nonce_disabled") or False
        }
        attestation_result, jwt_token = nvswitch_admin.attest(
            params, nonce, evidence_list
        )
    except Exception as e:
        logger.error("Error in NvSwitch Attestation using Local Verifier due to: %s", e)
        jwt_token = get_err_eat_token()
    return attestation_result, jwt_token


def get_err_eat_token(error_code=1, err_msg="NVSWITCH_ATTESTATION_ERR"):
    err_json = {"x-nv-err-message": err_msg, "x-nv-err-code": error_code}
    return jwt.encode(err_json, "secret", "HS256")
