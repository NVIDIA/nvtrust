#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import pytest
from nv_attestation_sdk import attestation
from nv_attestation_sdk.attestation import Attestation
import os
import json

@pytest.fixture
def attestation_policy():
    """Fixture to load the policy file"""
    file = "../../policies/local/NVSwitchLocalPolicyExample.json"
    with open(os.path.join(os.path.dirname(__file__), file)) as json_file:
        json_data = json.load(json_file)
        return json.dumps(json_data)

@pytest.mark.switch_hardware
@pytest.mark.skip(reason="Disabled until https://jirasw.nvidia.com/browse/ATTEST-2371 is implemented")
def test_successful_switch_attestation_without_service_key(attestation_policy, ocsp_url, rim_url):
    invoke_attestation(attestation_policy, None, ocsp_url, rim_url)

@pytest.mark.switch_hardware
@pytest.mark.skip(reason="Disabled until https://jirasw.nvidia.com/browse/ATTEST-2371 is implemented")
def test_successful_switch_attestation_with_valid_service_key(attestation_policy, service_key, ocsp_url, rim_url):
    assert service_key is not None, "Obtain a valid service key which has NVIDIA Attestation Service access from https://org.ngc.nvidia.com/service-keys"
    invoke_attestation(attestation_policy, service_key, ocsp_url, rim_url)

@pytest.mark.switch_hardware
@pytest.mark.skip(reason="Disabled until https://jirasw.nvidia.com/browse/ATTEST-2371 is implemented")
def test_fail_switch_attestation_with_invalid_service_key(attestation_policy, ocsp_url, rim_url):
    invoke_attestation(attestation_policy, "SOME_INVALID_SERVICE_KEY", ocsp_url, rim_url, is_attestation_successful=False)

def invoke_attestation(attestation_policy, service_key, ocsp_url, rim_url, is_attestation_successful=True):
    client = attestation.Attestation()
    client.set_name("thisNode1")
    if service_key is not None:
        client.set_service_key(service_key)
    client.set_nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")
    
    # Add verifier and check
    client.add_verifier(attestation.Devices.SWITCH, attestation.Environment.LOCAL, "", "", ocsp_url=ocsp_url, rim_url=rim_url)
    assert len(client.get_verifiers()) > 0
    
    # Get evidence and perform attestation
    evidence_list = client.get_evidence()
    assert client.attest(evidence_list) is is_attestation_successful
    
    if is_attestation_successful:
        # Validate token
        assert client.validate_token(attestation_policy) is True
        
        # Verify token can be decoded
        token = client.get_token()
        assert token is not None
        client.decode_token(token)

@pytest.fixture(autouse=True)
def reset():
    yield
    Attestation.reset()