#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""Config file for maintaining the dependant URLs for services and constants"""
import os

CERT_HOLD_STATUS = None
RIM_SERVICE_URL = os.getenv("NV_RIM_URL", "https://rim.attestation.nvidia.com/v1/rim/")
OCSP_SERVICE_URL = os.getenv("NV_OCSP_URL", "https://ocsp.ndis.nvidia.com/")
REMOTE_GPU_VERIFIER_SERVICE_URL = os.getenv(
    "NV_NRAS_GPU_URL", "https://nras.attestation.nvidia.com/v3/attest/gpu"
)
REMOTE_NVSWITCH_VERIFIER_SERVICE_URL = os.getenv(
    "NV_NRAS_NVSWITCH_URL", "https://nras.attestation.nvidia.com/v3/attest/switch"
)
# Planned to move the below to a list of acceptable GPU architectures
GPU_ARCH = "HOPPER"


def set_allow_hold_cert(value):
    global CERT_HOLD_STATUS
    CERT_HOLD_STATUS = value

def get_allow_hold_cert():
    global CERT_HOLD_STATUS
    if CERT_HOLD_STATUS is not None:
        return CERT_HOLD_STATUS
    else:
        return os.getenv("NV_ALLOW_HOLD_CERT") == "true"