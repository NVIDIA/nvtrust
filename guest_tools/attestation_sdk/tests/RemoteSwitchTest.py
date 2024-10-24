#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
from nv_attestation_sdk import attestation
import json
import os
import jwt

NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/switch"

client = attestation.Attestation()
client.set_name("thisNode1")
print ("[RemoteSwitchTest] node name :", client.get_name())
file = "policies/remote/v3/NVSwitchRemotePolicyExample.json"

client.set_nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")

client.add_verifier(attestation.Devices.SWITCH, attestation.Environment.REMOTE, NRAS_URL, "")

evidence_list = client.get_evidence()

client.attest(evidence_list)
print ("[RemoteSwitchTest] token : "+str(client.get_token()))
print ("[RemoteSwitchTest] call validate_token() - expecting True")

with open(os.path.join(os.path.dirname(__file__), file)) as json_file:
    json_data = json.load(json_file)
    remote_att_result_policy = json.dumps(json_data)
print(client.validate_token(remote_att_result_policy))

client.decode_token(client.get_token())


