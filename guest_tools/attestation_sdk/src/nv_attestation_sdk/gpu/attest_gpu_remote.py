#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module is responsible for remote attestation of GPU using NRAS API.
"""
import json
import logging
import requests
from verifier import cc_admin
from nv_attestation_sdk.utils.logging_config import get_logger
from ..utils import unified_eat_parser
from ..utils import nras_utils
from ..utils.config import REMOTE_GPU_VERIFIER_SERVICE_URL, GPU_ARCH, ATTESTATION_SERVICE_KEY
from ..utils.headers import OCSP_ALLOW_CERT_HOLD, SERVICE_KEY_VALUE
from ..utils.config import get_allow_hold_cert
logger = get_logger()


def get_evidence(nonce, options):
    """
    A function to get evidence for GPU to perform remote attestation.

    Parameters:
    nonce (int): A unique identifier for the evidence retrieval process.

    Returns:
    list: A list of GPU evidence collected for remote attestation.
    """
    try:
        ppcie_mode = options.get("ppcie_mode")

        logger.debug("Fetching evidence for GPU to perform remote attestation")
        gpu_evidence_list = cc_admin.collect_gpu_evidence_remote(nonce, ppcie_mode=ppcie_mode)
        logger.debug("Evidence list for GPU %s", gpu_evidence_list)
        return gpu_evidence_list
    except Exception as e:
        logger.error("Error in collecting evidences for GPU: %s", e)
    return []


def attest(nonce: str, gpu_evidence_list, attestation_options):
    """Verify GPU evidence with the Remote Verifier

    Args:
        nonce (_type_): Nonce represented as hex string
        gpu_evidence_list (_type_): GPU Evidence list
        attestation_options (dict): Arguments with which to perform attestation

    Returns:
        _type_: _description_
    """

    verifier_url = attestation_options.get('verifier_url') or REMOTE_GPU_VERIFIER_SERVICE_URL
    timeout = attestation_options.get('timeout') or 30
    service_key = attestation_options.get('service_key') or ATTESTATION_SERVICE_KEY

    attestation_result = False
    jwt_token = ""
    headers = {"Content-Type": "application/json"}
    if get_allow_hold_cert():
        headers[OCSP_ALLOW_CERT_HOLD] = "true"
    if service_key:
        headers['Authorization'] = SERVICE_KEY_VALUE.format(service_key)

    try:
        claims_version = attestation_options.get("claims_version") or "2.0"
        payload = build_payload(nonce, gpu_evidence_list, claims_version)
        logger.debug("NRAS URL for GPU Attestation: %s", verifier_url)
        logger.debug("Initiating GPU Attestation with NRAS")
        response = requests.request(
            "POST", verifier_url, headers=headers, data=payload, timeout=timeout
        )
        response_json = response.json()
        logger.debug(
            "Response received from NRAS for GPU Attestation: %s", response_json
        )
        logger.debug("Status code from NRAS for GPU Attestation: %s", response.status_code)
        if response.status_code == 200:
            jwt_token = response_json
            main_token_jwt = unified_eat_parser.get_overall_claims_token(jwt_token)
            decoded_main_token_json = nras_utils.decode_nras_token(
                verifier_url, main_token_jwt
            )
            attestation_result = decoded_main_token_json["x-nvidia-overall-att-result"]
            if attestation_result:
                logger.info("**** Attestation Successful ****")
            else:
                logger.error("**** Attestation Failed ****")
        else:
            logger.info("**** Attestation Failed ****")
            logger.error(
                "Error in GPU Attestation using NRAS due to: %s", response_json
            )
            logger.error("NRAS Response Code: %s", response.status_code)
    except Exception as e:
        logger.error(
            "Error in GPU Attestation using Remote Verifier due to: %s", e
        )
    return attestation_result, jwt_token


def build_payload(nonce, evidences, claims_version):
    """
    A function that builds a payload with the given nonce and list of evidences.
    """
    data = {"nonce": nonce, "evidence_list": evidences, "arch": GPU_ARCH, "claims_version": claims_version}
    return json.dumps(data)
