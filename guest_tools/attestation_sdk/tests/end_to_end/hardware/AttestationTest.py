#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import nv_attestation_sdk
from nv_attestation_sdk import attestation

## testing 
client = attestation.Attestation("inital-name")
print("Expecting initial-name")
print("node name :", client.get_name())

client.set_name("thisNode1")
print("Expecting ThisNode1")
print("node name :", client.get_name())

# will use the same singleton
client2 = attestation.Attestation()
print("Expecting ThisNode1")
print("node name :", client2.get_name())

my_evidence_policy = """version=1.0;
authorizationrules
{
   c:[type="secureBootEnabled", issuer=="AttestationService"]=> permit()
};

issuancerules
{
  c:[type="secureBootEnabled", issuer=="AttestationService"]=> issue(claim=c)
  c:[type="notSafeMode", issuer=="AttestationService"]=> issue(claim=c)
};"""

my_results_policy = """version=1.0;
authorizationrules
{
   c:[type="secureBootEnabled", issuer=="AttestationService"]=> permit()
};

issuancerules
{
  c:[type="secureBootEnabled", issuer=="AttestationService"]=> issue(claim=c)
  c:[type="notSafeMode", issuer=="AttestationService"]=> issue(claim=c)
};"""

print("Show verifiers - should be empty")
print(client.get_verifiers())

print("Add TEST CPU verifier")
client.add_verifier(attestation.Devices.CPU, attestation.Environment.TEST, "https://foo.com", my_evidence_policy)
print(client.get_verifiers())

print("Add TEST GPU verifier")
client.add_verifier(attestation.Devices.GPU, attestation.Environment.TEST, "https://foo.com", my_evidence_policy)
print(client.get_verifiers())

print("attest")
client.attest()

print("try to get_token() - should get token")
t = client.get_token()
print ("my token is : "+t)

print("try to get token with \"\" - should be nothing")
print ("my token is : "+client.get_token(""))

print("validate_token testing.  currently token is"+t)
print("call validate_token() - expecting True")
print(client.validate_token(""))

print("call validate_token(\"\") - expecting False")
print(client.validate_token("",""))

print("call validate_token(\"foo\") - expecting False")
print(client.validate_token("", "foo"))

print("call validate_token(<token<) - expecting true")
print(client.validate_token("", t))

print("call validate_token([]) - expecting False (it's a list)")
print(client.validate_token("", []))

print("call validate_token({}) - expecting False (it's an empty dict)")
print(client.validate_token("", {}))

print("before setting server - expecting null")
print(client.get_nonce())

print("set nonce")
print(client.set_nonce("0xdeadbeef"))

print("getting nonce - expecting deadbeef")
print(client.get_nonce())

print("generating nonce - expecting something completely differeng")
print(client._generate_nonce())

print("setting nonce server - good luck with that")
client.set_nonce_server("https://foo.com/nonce")

print("after setting server")
print(client._generate_nonce())


