from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin
from ..utils import unified_eat_parser
import json
import requests
from ..utils import nras_utils
import logging
logger = logging.getLogger("sdk-console")
file_logger = logging.getLogger("sdk-file")
from ..utils.config import REMOTE_NVSWITCH_VERIFIER_SERVICE_URL

def get_evidence(nonce):
    """Generate GPU evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    switch_evidence_list = nvswitch_admin.collect_evidence_remote(nonce)
    file_logger.info(f"switch_evidence_list is {switch_evidence_list}")
    return switch_evidence_list


def attest(nonce: str, gpu_evidence_list, verifier_url):
    """Verify GPU evidence with the Remote Verifier

    Args:
        nonce (_type_): Nonce represented as hex string
        gpu_evidence_list (_type_): GPU Evidence list
        verifier_url (str, optional): Verifier URL. Defaults to "https://nras.attestation.nvidia.com/v2/attest/gpu".

    Returns:
        _type_: _description_
    """
    if not verifier_url:
        verifier_url = REMOTE_NVSWITCH_VERIFIER_SERVICE_URL
    attestation_result = False
    jwt_token = ""
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        payload = build_payload(nonce, gpu_evidence_list)
        logger.info("Calling NRAS to attest nvSwitch evidence...")
        response = requests.request("POST", verifier_url, headers=headers, data=payload)
        response_json = response.json()
        file_logger.info(f"received NRAS response for nvSwitch verifier: {response_json}")
        if response.status_code == 200:
            jwt_token = response_json
            main_token_jwt = unified_eat_parser.get_overall_claims_token(jwt_token)
            decoded_main_token_json = nras_utils.decode_nras_token(verifier_url, main_token_jwt)
            attestation_result = decoded_main_token_json["x-nvidia-overall-att-result"]
            if attestation_result:
                logger.info("**** Attestation Successful ****")
            else:
                logger.info("******** Attestation Failed ****")
        else:
            logger.info("**** Attestation Failed ****")
    except Exception as e:
        logger.error(f"\tException: {e})")
    return attestation_result, jwt_token


def build_payload(nonce, evidences):
    data = {
        'nonce': nonce,
        'evidence_list': evidences,
        'arch': 'LS10'
    }
    return json.dumps(data)
