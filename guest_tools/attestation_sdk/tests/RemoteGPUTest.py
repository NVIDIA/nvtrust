#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk import attestation
import os 
import json

client = attestation.Attestation()
client.set_name("thisNode1")
client.set_nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")
print ("[RemoteGPUTest] node name :", client.get_name())

client.add_verifier(attestation.Devices.GPU, attestation.Environment.REMOTE, "https://nras.attestation.nvidia.com/v1/attest/gpu", "")

file = "NVGPURemotePolicyExample.json"

with open(os.path.join(os.path.dirname(__file__), file)) as json_file:
    json_data = json.load(json_file)
    remote_att_result_policy = json.dumps(json_data)

print(client.get_verifiers())

print ("[RemoteGPUTest] call attest() - expecting True")
print(client.attest())

print ("[RemoteGPUTest] token : "+str(client.get_token()))

print ("[RemoteGPUTest] call validate_token() - expecting True")
print(client.validate_token(remote_att_result_policy))
