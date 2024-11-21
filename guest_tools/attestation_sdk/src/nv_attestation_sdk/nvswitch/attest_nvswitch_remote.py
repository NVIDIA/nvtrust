#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module is responsible for remote attestation of Nvswitch using NRAS API.
"""

import logging
import json
import requests
from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin
from nv_attestation_sdk.utils.logging_config import get_logger
from ..utils.config import REMOTE_NVSWITCH_VERIFIER_SERVICE_URL
from ..utils import unified_eat_parser
from ..utils import nras_utils

logger = get_logger()


def get_evidence(nonce, ppcie_mode):
    """
    A function that fetches evidence for NvSwitch to perform remote attestation.

    Parameters:
    nonce (str): The nonce value for fetching evidence.

    Returns:
    list: A list of evidence for NvSwitch.
    """
    try:
        logger.debug("Fetching evidence for NvSwitch to perform local attestation")
        switch_evidence_list = nvswitch_admin.collect_evidence_remote(nonce, ppcie_mode=ppcie_mode)
        logger.debug("Evidence list for NvSwitch %s", switch_evidence_list)
        return switch_evidence_list
    except Exception as e:
        logger.error("Error in collecting evidences for Switch: %s", e)
    return []

def attest(nonce: str, gpu_evidence_list, verifier_url, timeout=30):
    """Verify GPU evidence with the Remote Verifier

    Args:
        nonce (_type_): Nonce represented as hex string
        gpu_evidence_list (_type_): GPU Evidence list
        verifier_url (str, optional): Verifier URL.
          Defaults to "https://nras.attestation.nvidia.com/v3/attest/gpu".
        timeout (int, optional): Timeout for the request. Defaults to 30.

    Returns:
        _type_: _description_
    """
    if not verifier_url:
        verifier_url = REMOTE_NVSWITCH_VERIFIER_SERVICE_URL
    attestation_result = False
    jwt_token = ""
    headers = {"Content-Type": "application/json"}
    try:
        payload = build_payload(nonce, gpu_evidence_list)
        logger.debug("NRAS URL for NvSwitch Attestation: %s", verifier_url)
        logger.debug("Initiating Nvswitch Attestation with NRAS")
        response = requests.request(
            "POST", verifier_url, headers=headers, data=payload, timeout=timeout
        )
        response_json = response.json()
        logger.debug(
            "Response received from NRAS for Nvswitch Attestation: %s", response_json
        )
        logger.debug("Status code from NRAS for Nvswitch Attestation: %s", response.status_code)
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
                logger.info("******** Attestation Failed ****")
        else:
            logger.info("**** Attestation Failed ****")
            logger.error(
                "Error in Nvswitch Attestation using NRAS due to: %s", response_json
            )
            logger.error("NRAS Response Code: %s", response.status_code)
    except Exception as e:
        logger.error("Error in Nvswitch Attestation using NRAS due to: %s", e)
    return attestation_result, jwt_token


def build_payload(nonce, evidences):
    """
    A function that builds a payload with the given nonce and list of evidences.
    """
    data = {"nonce": nonce, "evidence_list": evidences, "arch": "LS10"}
    return json.dumps(data)
