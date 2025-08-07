#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import pytest
import subprocess

DEFAULT_NRAS_GPU_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
DEFAULT_NRAS_SWITCH_URL = "https://nras.attestation.nvidia.com/v3/attest/switch"
DEFAULT_RIM_SERVICE_URL = "https://rim.attestation.nvidia.com/v1/rim/"
DEFAULT_OCSP_URL = "https://ocsp.ndis.nvidia.com/"
DEFAULT_TRUST_OUTPOST_RIM_SERVICE_URL = "https://rim.attestation.nvidia.com/v1/rim/"
DEFAULT_TRUST_OUTPOST_OCSP_URL = "https://ocsp.ndis.nvidia.com"

def pytest_addoption(parser):
    parser.addoption("--nras-gpu-url", action="store", default=DEFAULT_NRAS_GPU_URL,
                    help="NRAS URL for GPU attestation (default: %(default)s)")
    parser.addoption("--nras-switch-url", action="store", default=DEFAULT_NRAS_GPU_URL,
                    help="NRAS URL for Switch attestation (default: %(default)s)")
    parser.addoption("--rim-url", action="store", default=DEFAULT_RIM_SERVICE_URL,
                    help="RIM URL for attestation (default: %(default)s)")
    parser.addoption("--ocsp-url", action="store", default=DEFAULT_OCSP_URL,
                    help="OCSP URL for attestation (default: %(default)s)")
    parser.addoption("--trust-outpost-rim-url", action="store", default=DEFAULT_TRUST_OUTPOST_RIM_SERVICE_URL,
                    help="RIM URL for Trust Outpost attestation (default: %(default)s)")
    parser.addoption("--trust-outpost-ocsp-url", action="store", default=DEFAULT_TRUST_OUTPOST_OCSP_URL,
                    help="OCSP URL for Trust Outpost attestation (default: %(default)s)")
    parser.addoption("--service-key", action="store", default=None,
                    help="Service key for calling attestation services (default: %(default)s)")

@pytest.fixture(autouse=True)
def nras_gpu_url(request, monkeypatch):
    """Fixture to get the NRAS GPU URL from command line or use default.  This also sets the environment variable NV_NRAS_GPU_URL"""
    nras_gpu_url = request.config.getoption("--nras-gpu-url")
    if nras_gpu_url is not None:
        monkeypatch.setenv("NV_NRAS_GPU_URL", nras_gpu_url)
    return nras_gpu_url

@pytest.fixture(autouse=True)
def nras_switch_url(request, monkeypatch):
    """Fixture to get the NRAS Switch URL from command line or use default.  This also sets the environment variable NV_NRAS_NVSWITCH_URL"""
    nras_switch_url = request.config.getoption("--nras-switch-url")
    if nras_switch_url is not None:
        monkeypatch.setenv("NV_NRAS_NVSWITCH_URL", nras_switch_url)
    return nras_switch_url

@pytest.fixture(autouse=True)
def rim_url(request, monkeypatch):
    """Fixture to get the RIM URL from command line or use default.  This also sets the environment variable NV_RIM_URL"""
    rim_url = request.config.getoption("--rim-url")
    if rim_url is not None:
        monkeypatch.setenv("NV_RIM_URL", rim_url)
    return rim_url

@pytest.fixture(autouse=True)
def trust_outpost_rim_url(request, monkeypatch):
    """Fixture to get the Trust Outpost RIM URL from command line or use default.  This also sets the environment variable NV_RIM_URL"""
    trust_outpost_rim_url = request.config.getoption("--trust-outpost-rim-url")
    if trust_outpost_rim_url is not None:
        monkeypatch.setenv("NV_RIM_URL", trust_outpost_rim_url)
    return trust_outpost_rim_url

@pytest.fixture
def ocsp_url(request, monkeypatch):
    """Fixture to get the OCSP URL from command line or use default.  This also sets the environment variable NV_OCSP_URL"""
    ocsp_url = request.config.getoption("--ocsp-url")
    if ocsp_url is not None:
        monkeypatch.setenv("NV_OCSP_URL", ocsp_url)
    return ocsp_url

@pytest.fixture
def trust_outpost_ocsp_url(request, monkeypatch):
    """Fixture to get the Trust Outpost OCSP URL from command line or use default.  This also sets the environment variable NV_OCSP_URL"""
    trust_outpost_ocsp_url = request.config.getoption("--trust-outpost-ocsp-url")
    if trust_outpost_ocsp_url is not None:
        monkeypatch.setenv("NV_OCSP_URL", trust_outpost_ocsp_url)
    return trust_outpost_ocsp_url

@pytest.fixture
def service_key(request):
    """Fixture to get the service key from command line or use default"""
    return request.config.getoption("--service-key")
