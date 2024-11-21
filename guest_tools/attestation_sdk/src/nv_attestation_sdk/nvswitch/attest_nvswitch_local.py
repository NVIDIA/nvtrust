#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module is responsible for local attestation of Nvswitch using nvswitch-verifier.
"""
import logging
import jwt
from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin
from ..utils.config import RIM_SERVICE_URL, OCSP_SERVICE_URL, ALLOW_HOLD_CERT
from nv_attestation_sdk.utils.logging_config import get_logger

logger = get_logger()


def get_evidence(nonce, ppcie_mode: bool):
    """
    A function that fetches evidence for NvSwitch to perform local attestation.

    Parameters:
    nonce (str): The nonce value for fetching evidence.

    Returns:
    list: A list of evidence for NvSwitch.
    """
    try:
        logger.debug("Fetching evidence for NvSwitch to perform local attestation")
        switch_evidence_list = nvswitch_admin.collect_evidence(nonce, ppcie_mode=ppcie_mode)
        logger.debug("Evidence list for NvSwitch %s", switch_evidence_list)
        return switch_evidence_list
    except Exception as e:
        logger.error("Error in collecting evidences for switches: %s", e)
    return []


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
        params = {
            "verbose": False,
            "test_no_gpu": False,
            "driver_rim": None,
            "vbios_rim": None,
            "user_mode": True,
            "rim_root_cert": None,
            "rim_service_url": RIM_SERVICE_URL,
            "allow_hold_cert": ALLOW_HOLD_CERT,
            "ocsp_url": OCSP_SERVICE_URL,
            "nonce": nonce,
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
