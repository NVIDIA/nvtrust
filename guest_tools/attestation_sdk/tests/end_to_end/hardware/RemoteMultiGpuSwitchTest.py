#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk import attestation
import os
import json

NRAS_URL_GPU = "https://nras.attestation.nvidia.com/v3/attest/gpu"
client = attestation.Attestation()
client.set_name("q")
client.set_nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")

print("[RemoteGPUTest] node name :", client.get_name())

client.add_verifier(attestation.Devices.GPU, attestation.Environment.REMOTE, NRAS_URL_GPU, "")
print(client.get_verifiers())

print("[RemoteGPUTest] call get_evidence()")
evidence_list = client.get_evidence(ppcie_mode=False)

print("[RemoteGPUTest] call attest() - expecting True")
print(client.attest(evidence_list))

print("[RemoteGPUTest] token : " + str(client.get_token()))
print("[RemoteGPUTest] call validate_token() - expecting True")

file = "../../policies/remote/v3/NVGPURemotePolicyExample.json"
with open(os.path.join(os.path.dirname(__file__), file)) as json_file:
    json_data = json.load(json_file)
    remote_att_result_policy = json.dumps(json_data)
print(client.validate_token(remote_att_result_policy))

client.decode_token(client.get_token())

NRAS_SWITCH_URL = "https://nras.attestation.nvidia.com/v3/attest/switch"

client.clear_verifiers()
client.set_name("thisNode1")
print ("[RemoteSwitchTest] node name :", client.get_name())
file = "policies/remote/v3/NVSwitchRemotePolicyExample.json"

client.set_nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")

client.add_verifier(attestation.Devices.SWITCH, attestation.Environment.REMOTE, NRAS_SWITCH_URL, "")

evidence_list = client.get_evidence(ppcie_mode=False)

client.attest(evidence_list)
print ("[RemoteSwitchTest] token : "+str(client.get_token()))
print ("[RemoteSwitchTest] call validate_token() - expecting True")

with open(os.path.join(os.path.dirname(__file__), file)) as json_file:
    json_data = json.load(json_file)
    remote_att_result_policy = json.dumps(json_data)
print(client.validate_token(remote_att_result_policy))

client.decode_token(client.get_token())



