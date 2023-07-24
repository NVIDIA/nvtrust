#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../')
import src.nv_attestation_sdk.attestation as attestation
# from nv_attestation_sdk import *
# location of src

## testing
client = attestation.Attestation()
client.set_name("thisNode1")
print("node name :", client.get_name())

#client.add_verifier(attestation.Devices.CPU, attestation.Environment.LOCAL, "https://foo.com")
client.add_verifier(attestation.Devices.GPU, attestation.Environment.LOCAL, "", "", "")

client.attest()

