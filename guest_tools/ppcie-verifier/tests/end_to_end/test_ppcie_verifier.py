#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk.attestation import Attestation
import pytest
import subprocess

DEFAULT_RIM_SERVICE_URL = "https://rim.attestation.nvidia.com/v1/rim/"
DEFAULT_OCSP_URL = "https://ocsp.ndis.nvidia.com/"

def pytest_addoption(parser):
    parser.addoption("--rim-url", action="store", default=DEFAULT_RIM_SERVICE_URL,
                    help="RIM URL for attestation (default: %(default)s)")
    parser.addoption("--ocsp-url", action="store", default=DEFAULT_OCSP_URL,
                    help="OCSP URL for attestation (default: %(default)s)")
    parser.addoption("--service-key", action="store", default=None,
                    help="Service key for calling attestation services (default: %(default)s)")

@pytest.fixture
def rim_url(request):
    """Fixture to get the RIM URL from command line or use default"""
    return request.config.getoption("--rim-url")

@pytest.fixture
def ocsp_url(request):
    """Fixture to get the OCSP URL from command line or use default"""
    return request.config.getoption("--ocsp-url")

@pytest.fixture
def service_key(request):
    """Fixture to get the service key from command line or use default"""
    return request.config.getoption("--service-key")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_successful_local_ppcie_attestation_with_valid_service_key(service_key, rim_url, ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, rim_url, ocsp_url, "LOCAL")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_fail_local_ppcie_attestation_with_invalid_service_key(rim_url, ocsp_url):
    invoke_attestation("SOME_INVALID_SERVICE_KEY", rim_url, ocsp_url, "LOCAL", return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_successful_remote_ppcie_attestation_with_valid_service_key(service_key, rim_url, ocsp_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(service_key, rim_url, ocsp_url, "REMOTE")

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_fail_remote_ppcie_attestation_with_invalid_service_key(rim_url, ocsp_url):
    invoke_attestation("SOME_INVALID_SERVICE_KEY", rim_url, ocsp_url, "REMOTE", return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_fail_ppcie_attestation_on_SPT_machine(rim_url, ocsp_url):
    invoke_attestation(None, rim_url, ocsp_url, "REMOTE", return_code=1)

@pytest.mark.gpu_hardware
@pytest.mark.switch_hardware
@pytest.mark.user_mode
def test_fail_with_invalid_combination_of_mode(rim_url, ocsp_url):
    command = [
        'python3', 
        '-m', 
        'ppcie.verifier.verification',
        '--gpu-attestation-mode',
        "LOCAL",
        '--switch-attestation-mode',
        "REMOTE",
        '--claims_version',
        "2.0",
        '--rim-url',
        rim_url,
        '--ocsp-url',
        ocsp_url
    ]

    invoke_attestation(command, return_code=1)

def invoke_attestation(service_key, rim_url, ocsp_url, attestation_mode, claims_version="2.0", ocsp_nonce_disabled=False, is_user_mode=False, return_code=0):
    command = [
        'python3', 
        '-m', 
        'ppcie.verifier.verification',
        '--gpu-attestation-mode',
        attestation_mode,
        '--switch-attestation-mode',
        attestation_mode,
        '--claims_version',
        claims_version,
        '--rim-url',
        rim_url,
        '--ocsp-url',
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
    if return_code == 0:
        assert "PPCIE: GPU state is READY" in result.stdout
    if return_code == 1:
        assert "PPCIE: GPU state is NOT READY" in result.stdout

def invoke_attestation(command, return_code):
    result = subprocess.run(command, capture_output=True, text=True)
    
    assert result.returncode == return_code
    if return_code == 0:
        assert "PPCIE: GPU state is READY" in result.stdout
    if return_code == 1:
        assert "PPCIE: GPU state is NOT READY" in result.stdout

@pytest.fixture(autouse=True)
def reset():
    yield
    Attestation.reset()