#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

import requests
from ..utils import unified_eat_parser
from ..utils import nras_utils
import json
import logging

from ..utils.config import REMOTE_GPU_VERIFIER_SERVICE_URL, GPU_ARCH

console_logger = logging.getLogger("sdk-console")
file_logger = logging.getLogger("sdk-file")


def get_evidence(nonce):
    """Generate GPU evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    from verifier import cc_admin
    gpu_evidence_list = cc_admin.collect_gpu_evidence_remote(nonce)
    return gpu_evidence_list


def attest(nonce: str, gpu_evidence_list, verifier_url):
    """Verify GPU evidence with the Remote Verifier

    Args:
        nonce (_type_): Nonce represented as hex string
        gpu_evidence_list (_type_): GPU Evidence list
        verifier_url (str, optional): Verifier URL.

    Returns:
        _type_: _description_
    """

    if not verifier_url:
        verifier_url = REMOTE_GPU_VERIFIER_SERVICE_URL

    attestation_result = False
    jwt_token = ""
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        payload = build_payload(nonce, gpu_evidence_list)
        file_logger.info(f"verifier_url is {verifier_url}")
        file_logger.info("Calling NRAS to attest GPU evidence...")
        response = requests.request("POST", verifier_url, headers=headers, data=payload)
        response_json = response.json()
        file_logger.info(f"received NRAS response: {response_json}")
        if response.status_code == 200:
            jwt_token = response_json
            main_token_jwt = unified_eat_parser.get_overall_claims_token(jwt_token)
            decoded_main_token_json = nras_utils.decode_nras_token(verifier_url, main_token_jwt)
            attestation_result = decoded_main_token_json["x-nvidia-overall-att-result"]
            if attestation_result:
                console_logger.info("**** Attestation Successful ****")
            else:
                console_logger.error("**** Attestation Failed ****")
        else:
            console_logger.info("**** Attestation Failed ****")
    except Exception as e:
        console_logger.error("\tException: ", e)
    return attestation_result, jwt_token


def build_payload(nonce, evidences):
    data = {
        'nonce': nonce,
        'evidence_list': evidences,
        'arch': GPU_ARCH
    }
    return json.dumps(data)
