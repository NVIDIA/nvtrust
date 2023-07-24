#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import json
import jwt
from verifier import cc_admin


def validate_gpu_token(gpu_token: str, policy: str):
    if policy == "" or gpu_token == "":
        return False

    policy_obj = json.loads(policy)
    gpu_token_obj = jwt.decode(gpu_token, algorithms='HS256', verify=False, key="secret")
    auth_rules = policy_obj['authorization-rules']
    for key in auth_rules:
        if not (key in gpu_token_obj and gpu_token_obj[key] == auth_rules[key]):
            print("\t[ERROR] Invalid token. Authorized claims does not match the appraisal policy: ", key)
            return False
    return True


def attest_gpu_local():
    attestation_result = False
    jwt_token = ""
    try:
        params = {"verbose": False,
                  "test_no_gpu": False,
                  "driver_rim": "/usr/share/nvidia/rim/RIM_GH100PROD.swidtag",
                  "vbios_rim": None,
                  "user_mode": True}
        attestation_result, jwt_token = cc_admin.attest(params)
    except Exception as e:
        print("\tException: ", e)
        jwt_token = jwt.encode({'x-nv-err-message': "GPU_ATTESTATION_ERR"},
                               'secret',
                               "HS256")
    return attestation_result, jwt_token
