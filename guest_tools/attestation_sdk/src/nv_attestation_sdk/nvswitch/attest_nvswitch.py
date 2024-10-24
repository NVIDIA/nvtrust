#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import logging
file_logger = logging.getLogger("sdk-file")


def get_evidence(nonce):
    """Get nvSwitch evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    file_logger.info("get_evidence")
    from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin
    evidence_list = nvswitch_admin.collect_evidence(nonce)
    file_logger.debug(f"evidence_list: ${evidence_list}")
    return evidence_list
