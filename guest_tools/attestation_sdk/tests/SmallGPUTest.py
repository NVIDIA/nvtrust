#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk import attestation

client = attestation.Attestation()
client.set_name("thisNode1")
print ("[SmallGPUTest] node name :", client.get_name())

client.add_verifier(attestation.Devices.GPU, attestation.Environment.LOCAL, "", "")
attestation_results_policy = '{"version":"1.0","authorization-rules":{"x-nv-gpu-available":true,' \
                             '"x-nv-gpu-attestation-report-available":true,"x-nv-gpu-info-fetched":true,' \
                             '"x-nv-gpu-arch-check":true,"x-nv-gpu-root-cert-available":true,' \
                             '"x-nv-gpu-cert-chain-verified":true,"x-nv-gpu-ocsp-cert-chain-verified":true,' \
                             '"x-nv-gpu-ocsp-signature-verified":true,"x-nv-gpu-cert-ocsp-nonce-match":true,' \
                             '"x-nv-gpu-cert-check-complete":true,"x-nv-gpu-measurement-available":true,' \
                             '"x-nv-gpu-attestation-report-parsed":true,"x-nv-gpu-nonce-match":true,' \
                             '"x-nv-gpu-attestation-report-driver-version-match":true,' \
                             '"x-nv-gpu-attestation-report-vbios-version-match":true,' \
                             '"x-nv-gpu-attestation-report-verified":true,"x-nv-gpu-driver-rim-schema-fetched":true,' \
                             '"x-nv-gpu-driver-rim-schema-validated":true,"x-nv-gpu-driver-rim-cert-extracted":true,' \
                             '"x-nv-gpu-driver-rim-signature-verified":true,' \
                             '"x-nv-gpu-driver-rim-driver-measurements-available":true,' \
                             '"x-nv-gpu-driver-vbios-rim-fetched":true,"x-nv-gpu-vbios-rim-schema-validated":true,' \
                             '"x-nv-gpu-vbios-rim-cert-extracted":true,"x-nv-gpu-vbios-rim-signature-verified":true,' \
                             '"x-nv-gpu-vbios-rim-driver-measurements-available":true,' \
                             '"x-nv-gpu-vbios-index-conflict":true,"x-nv-gpu-measurements-match":true}}'

print(client.get_verifiers())

print ("[SmallGPUTest] call attest() - expecting True")
print(client.attest())

print ("[SmallGPUTest] token : "+str(client.get_token()))

print ("[SmallGPUTest] call validate_token() - expecting True")
print(client.validate_token(attestation_results_policy))


