#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#


def get_evidence(nonce):
    """Generate GPU evidence

    Args:
        nonce (str, optional): Nonce represented as hex string. Defaults to "".

    Returns:
        _type_: GPU evidence
    """
    from verifier import cc_admin

    gpu_evidence_list = cc_admin.collect_gpu_evidence(nonce)
    return gpu_evidence_list
