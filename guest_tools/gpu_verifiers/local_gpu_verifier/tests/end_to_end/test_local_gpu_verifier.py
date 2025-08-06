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
def test_successful_gpu_attestation_without_service_key(rim_url, ocsp_url):
    invoke_attestation(None, rim_url, ocsp_url)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_with_valid_service_key(service_key, rim_url, ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, rim_url, ocsp_url)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_successful_gpu_attestation_with_claims_version_3_0(service_key, rim_url, ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, rim_url, ocsp_url, claims_version="3.0")

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_fail_gpu_attestation_with_invalid_service_key(rim_url, ocsp_url):
    invoke_attestation("SOME_INVALID_SERVICE_KEY", rim_url, ocsp_url, is_user_mode=True, return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_fail_gpu_attestation_with_invalid_RIM_url(ocsp_url):
    invoke_attestation(None, "http://invalid-rim-url.com", ocsp_url, return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.user_mode
def test_fail_gpu_attestation_with_invalid_claims_version(rim_url, ocsp_url):
    invoke_attestation(None, rim_url, ocsp_url, claims_version="INVALID_CLAIMS_VERSION", return_code=2)

def invoke_attestation(service_key, rim_url, ocsp_url, is_user_mode=False, claims_version="2.0", return_code=0):
    command = [
        'python3', 
        '-m', 
        'verifier.cc_admin',
        '--rim_service_url',
        rim_url,
        '--ocsp_url',
        ocsp_url,
        '--claims_version',
        claims_version
    ]
    if is_user_mode:
        command.append('--user_mode')
    
    if service_key is not None:
        command.append('--service_key')
        command.append(service_key)
    
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == return_code
    if return_code == 0:
        assert "GPU Attestation is Successful" in result.stdout
    if return_code == 1:
        assert "GPU Attestation failed" in result.stdout

@pytest.fixture(autouse=True)
def reset():
    yield
    Attestation.reset()
