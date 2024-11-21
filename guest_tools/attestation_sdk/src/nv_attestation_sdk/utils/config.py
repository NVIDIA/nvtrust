#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""Config file for maintaining the dependant URLs for services and constants"""
import os

RIM_SERVICE_URL = os.getenv("NV_RIM_URL", "https://rim.attestation.nvidia.com/v1/rim/")
ALLOW_HOLD_CERT = True
OCSP_SERVICE_URL = os.getenv("NV_OCSP_URL", "https://ocsp.ndis.nvidia.com/")
REMOTE_GPU_VERIFIER_SERVICE_URL = os.getenv(
    "NV_NRAS_GPU_URL", "https://nras.attestation.nvidia.com/v3/attest/gpu"
)
REMOTE_NVSWITCH_VERIFIER_SERVICE_URL = os.getenv(
    "NV_NRAS_NVSWITCH_URL", "https://nras.attestation.nvidia.com/v3/attest/nvswitch"
)
# Planned to move the below to a list of acceptable GPU architectures
GPU_ARCH = "HOPPER"
