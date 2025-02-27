#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

from nv_attestation_sdk import attestation

client = attestation.Attestation("thisNode44")
print("node name :", client.get_name())

client.add_verifier(attestation.Devices.GPU, attestation.Environment.LOCAL, "", "")
print(client.get_verifiers())

client.add_verifier(attestation.Devices.CPU, attestation.Environment.TEST, "", "")
print(client.get_verifiers())

print("call attest() - expecting True")
print(client.attest())

t = client.get_token()
print ("my token is : "+t)

print("call validate_token() - expecting True")

attestation_results_policy = '{"version":"1.0","authorization-rules":{"x-nvidia-gpu-arch-check":true,"x-nvidia-gpu-attestation-report-cert-chain-validated":true,"x-nvidia-gpu-attestation-report-parsed":true,"x-nvidia-gpu-nonce-match":true,"x-nv-gpu-attestation-report-driver-version-match":true,"x-nv-gpu-attestation-report-vbios-version-match":true,"x-nv-gpu-attestation-report-signature-verified":true,"x-nvidia-gpu-driver-rim-fetched":true,"x-nvidia-gpu-driver-rim-schema-validated":true,"x-nvidia-gpu-driver-rim-cert-validated":true,"x-nvidia-gpu-driver-rim-signature-verified":true,"x-nvidia-gpu-driver-rim-driver-measurements-available":true,"x-nvidia-gpu-driver-vbios-rim-fetched":true,"x-nvidia-gpu-vbios-rim-schema-validated":true,"x-nvidia-gpu-vbios-rim-cert-validated":true,"x-nvidia-gpu-vbios-rim-signature-verified":true,"x-nvidia-gpu-vbios-rim-measurements-available":true,"x-nvidia-gpu-vbios-index-no-conflict":true,"x-nvidia-gpu-measurements-match":true}}'
print(client.validate_token(attestation_results_policy, t))


