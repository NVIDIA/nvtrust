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

attestation_results_policy = '{"version":"1.0","authorization-rules":{"x-nv-gpu-available":true,"x-nv-gpu-attestation-report-available":true,"x-nv-gpu-info-fetched":true,"x-nv-gpu-arch-check":true,"x-nv-gpu-root-cert-available":true,"x-nv-gpu-cert-chain-verified":true,"x-nv-gpu-ocsp-cert-chain-verified":true,"x-nv-gpu-ocsp-signature-verified":true,"x-nv-gpu-cert-ocsp-nonce-match":true,"x-nv-gpu-cert-check-complete":true,"x-nv-gpu-measurement-available":true,"x-nv-gpu-attestation-report-parsed":true,"x-nv-gpu-nonce-match":true,"x-nv-gpu-attestation-report-driver-version-match":true,"x-nv-gpu-attestation-report-vbios-version-match":true,"x-nv-gpu-attestation-report-verified":true,"x-nv-gpu-driver-rim-schema-fetched":true,"x-nv-gpu-driver-rim-schema-validated":true,"x-nv-gpu-driver-rim-cert-extracted":true,"x-nv-gpu-driver-rim-signature-verified":true,"x-nv-gpu-driver-rim-driver-measurements-available":true,"x-nv-gpu-driver-vbios-rim-fetched":true,"x-nv-gpu-vbios-rim-schema-validated":true,"x-nv-gpu-vbios-rim-cert-extracted":true,"x-nv-gpu-vbios-rim-signature-verified":true,"x-nv-gpu-vbios-rim-driver-measurements-available":true,"x-nv-gpu-vbios-index-no-conflict":true,"x-nv-gpu-measurements-match":true}}'
print(client.validate_token(attestation_results_policy, t))


