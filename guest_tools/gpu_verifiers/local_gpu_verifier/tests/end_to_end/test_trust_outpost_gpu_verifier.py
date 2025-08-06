#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk.attestation import Attestation
import pytest
import subprocess

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_without_service_key(trust_outpost_rim_url, trust_outpost_ocsp_url):
    invoke_attestation(None, False, trust_outpost_rim_url, trust_outpost_ocsp_url, return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_without_service_key_with_ocsp_nonce_disabled(trust_outpost_rim_url, trust_outpost_ocsp_url):
    invoke_attestation(None, True, trust_outpost_rim_url, trust_outpost_ocsp_url, return_code=0)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_with_valid_service_key(service_key, trust_outpost_rim_url, trust_outpost_ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, False, trust_outpost_rim_url, trust_outpost_ocsp_url, return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_with_valid_service_key_with_ocsp_nonce_disabled(service_key, trust_outpost_rim_url, trust_outpost_ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, True, trust_outpost_rim_url, trust_outpost_ocsp_url, return_code=0)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_with_invalid_service_key(service_key, trust_outpost_rim_url, trust_outpost_ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation("SOME_INVALID_SERVICE_KEY", True, trust_outpost_rim_url, trust_outpost_ocsp_url, return_code=0)

def invoke_attestation(service_key, ocsp_nonce_disabled, rim_url, ocsp_url, is_user_mode=True, return_code=0):
    command = [
        'python3', 
        '-m', 
        'verifier.cc_admin',
        '--rim_service_url',
        rim_url,
        '--ocsp_url',
        ocsp_url
    ]

    if is_user_mode:
        command.append('--user_mode')
    
    if service_key is not None:
        command.append('--service_key')
        command.append(service_key)
    
    if ocsp_nonce_disabled:
        command.append('--ocsp_nonce_disabled')

    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == return_code
    attestation_result = "GPU Attestation is Successful" if return_code == 0 else "GPU Attestation failed"
    assert attestation_result in result.stdout

@pytest.fixture(autouse=True)
def reset():
    yield
    Attestation.reset()