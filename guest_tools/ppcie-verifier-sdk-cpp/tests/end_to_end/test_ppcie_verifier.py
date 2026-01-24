#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import pytest
import subprocess
import os

# Get the test data directory path
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
def test_successful_local_ppcie_attestation():
    relying_party_policy = os.path.join(TEST_DATA_DIR, "relying_party_policy.rego")
    invoke_attestation(verifier="local", nonce="0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb", relying_party_policy=relying_party_policy, rim_url="https://rim-internal.attestation.nvidia.com/internal", ocsp_url="https://ocsp.ndis-stg.nvidia.com", nras_url="https://nras.attestation-stg.nvidia.com")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
def test_successful_remote_ppcie_attestation():
    relying_party_policy = os.path.join(TEST_DATA_DIR, "relying_party_policy.rego")
    invoke_attestation(verifier="remote", nonce="0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb", relying_party_policy=relying_party_policy, rim_url="https://rim-internal.attestation.nvidia.com/internal", ocsp_url="https://ocsp.ndis-stg.nvidia.com", nras_url="https://nras.attestation-stg.nvidia.com")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
def test_successful_local_ppcie_attestation_with_file_evidence():
    gpu_evidence = os.path.join(TEST_DATA_DIR, "gpu_evidence.json")
    switch_evidence = os.path.join(TEST_DATA_DIR, "switch_evidence.json")
    relying_party_policy = os.path.join(TEST_DATA_DIR, "relying_party_policy.rego")
    invoke_attestation(verifier="local", nonce="0x4760e30534a0621357d458b1a7936551b5dc4cd1e69718adf7ed9fb0252a537e", gpu_evidence=gpu_evidence, switch_evidence=switch_evidence, relying_party_policy=relying_party_policy, rim_url="https://rim-internal.attestation.nvidia.com/internal", ocsp_url="https://ocsp.ndis-stg.nvidia.com", nras_url="https://nras.attestation-stg.nvidia.com")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
def test_successful_remote_ppcie_attestation_with_file_evidence():
    gpu_evidence = os.path.join(TEST_DATA_DIR, "gpu_evidence.json")
    switch_evidence = os.path.join(TEST_DATA_DIR, "switch_evidence.json")
    relying_party_policy = os.path.join(TEST_DATA_DIR, "relying_party_policy.rego")
    invoke_attestation(verifier="remote", nonce="0x4760e30534a0621357d458b1a7936551b5dc4cd1e69718adf7ed9fb0252a537e", gpu_evidence=gpu_evidence, switch_evidence=switch_evidence, relying_party_policy=relying_party_policy, rim_url="https://rim-internal.attestation.nvidia.com/internal", ocsp_url="https://ocsp.ndis-stg.nvidia.com", nras_url="https://nras.attestation-stg.nvidia.com")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
def test_successful_local_ppcie_attestation_with_service_key():
    relying_party_policy = os.path.join(TEST_DATA_DIR, "relying_party_policy.rego")
    service_key = os.environ.get("NVIDIA_ATTESTATION_SERVICE_KEY")
    if not service_key:
        pytest.skip("NVIDIA_ATTESTATION_SERVICE_KEY environment variable not set")
    invoke_attestation(verifier="local", nonce="0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb", relying_party_policy=relying_party_policy, rim_url="https://rim-internal.attestation.nvidia.com/internal", ocsp_url="https://ocsp.ndis-stg.nvidia.com", nras_url="https://nras.attestation-stg.nvidia.com", service_key=service_key)

def invoke_attestation(verifier="local", nonce=None, gpu_evidence=None, switch_evidence=None, relying_party_policy=None, rim_url=None, ocsp_url=None, nras_url=None, service_key=None, return_code=0):
    command = [
        'python3',
        '-m',
        'ppcie.verifier.verification',
        '--verifier',
        verifier,
        '--log-level',
        'info'
    ]

    if nonce is not None:
        command.extend(['--nonce', nonce])

    if relying_party_policy is not None:
        command.extend(['--relying-party-policy', relying_party_policy])

    if rim_url is not None:
        command.extend(['--rim-url', rim_url])

    if ocsp_url is not None:
        command.extend(['--ocsp-url', ocsp_url])

    if nras_url is not None:
        command.extend(['--nras-url', nras_url])

    if gpu_evidence is not None:
        command.extend(['--gpu-evidence', gpu_evidence])

    if switch_evidence is not None:
        command.extend(['--switch-evidence', switch_evidence])

    if service_key is not None:
        command.extend(['--service-key', service_key])

    result = subprocess.run(command, capture_output=True, text=True)
    
    print(result.stdout)
    
    assert result.returncode == return_code
