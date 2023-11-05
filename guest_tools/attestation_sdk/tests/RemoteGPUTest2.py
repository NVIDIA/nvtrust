#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk.gpu import attest_gpu_remote
import secrets
nonce = secrets.token_bytes(32).hex()

evidence = attest_gpu_remote.generate_evidence(nonce)
print(evidence)

verify_result = attest_gpu_remote.verify_evidence(nonce,evidence, "https://nras.attestation.nvidia.com/v1/attest/gpu")

print(verify_result)