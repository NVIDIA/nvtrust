#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module is responsible for local attestation of GPUs using local gpu verifier.
"""
import logging
import jwt

from verifier import cc_admin
from nv_attestation_sdk.utils.logging_config import get_logger
from ..utils.config import RIM_SERVICE_URL, OCSP_SERVICE_URL, ATTESTATION_SERVICE_KEY
from ..utils.config import get_allow_hold_cert
logger = get_logger()


def get_evidence(nonce, options):
    """
    A function to get evidence for GPU to perform local attestation.

    Parameters:
    nonce (int): A unique identifier for the evidence retrieval process.

    Returns:
    list: A list of GPU evidence collected for local attestation.
    """
    try:
        logger.debug("Fetching evidence for GPU to perform local attestation")
        gpu_evidence_list = cc_admin.collect_gpu_evidence_local(nonce, ppcie_mode=options.get("ppcie_mode"), no_gpu_mode=options.get("no_gpu_mode"))
        logger.debug("Evidence list for GPU %s", gpu_evidence_list)
        return gpu_evidence_list
    except Exception as e:
        logger.error("Error in collecting evidences for GPU: %s", e)
    return []


def attest(nonce: str, gpu_evidence_list, attestation_options):
    """Attest a device locally

    Args:
        nonce (str): Nonce as hex string
        gpu_evidence_list (_type_): GPU evidence list
        attestation_options (dict): Arguments with which to perform attestation

    Returns:
        Attestation result and JWT token
    """
    attestation_result = False

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
            "ppcie_mode": attestation_options.get("ppcie_mode") or True,
            'ocsp_nonce_disabled': attestation_options.get("ocsp_nonce_disabled") or False,
            "service_key": attestation_options.get("service_key") or ATTESTATION_SERVICE_KEY,
            "claims_version": attestation_options.get("claims_version") or "2.0"
        }
        attestation_result, jwt_token = cc_admin.attest(
            params, nonce, gpu_evidence_list
        )
    except Exception as e:
        logger.error("Error in GPU Attestation using Local Verifier due to: %s", e)
        jwt_token = get_err_eat_token()
    return attestation_result, jwt_token


def get_err_eat_token(error_code=1, err_msg="GPU_ATTESTATION_ERR"):
    err_json = {"x-nv-err-message": err_msg, "x-nv-err-code": error_code}
    return jwt.encode(err_json, "secret", "HS256")
