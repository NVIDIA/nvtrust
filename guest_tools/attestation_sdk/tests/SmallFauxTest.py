#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

from nv_attestation_sdk import attestation

client = attestation.Attestation("have a nice day")
print("node name :", client.get_name())

client.add_verifier(attestation.Devices.CPU, attestation.Environment.TEST, "", "")
print(client.get_verifiers())

print("call attest() - expecting True")
print(client.attest())

print ("my token is : "+str(client.get_token()))

print("call validate_token() - expecting True")
print(client.validate_token(""))


