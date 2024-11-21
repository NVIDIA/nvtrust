import base64
import json
import unittest
import jwt
import os
from nv_attestation_sdk.utils.local_utils import validate_token
local_gpu_policy_file = "../../policies/local/NVGPULocalPolicyExample.json"
overall_claims_file_path = "tests/pytests/data/gpu/overall_claims_local.json"
detached_claims_file_path = "tests/pytests/data/gpu/detached_claims_local.json"
class LocalUtilsTest(unittest.TestCase):

    def test_validate_claims(self):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        token = [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(validate_token("http//test", token, remote_att_result_policy))

    def test_validate_claims_fails_with_incorrect_jwt_type(self):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        token = [
            ["JWT1", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(validate_token("http//test", token, remote_att_result_policy))

    def test_validate_claims_fails_with_unknown_claim_in_detached_policy(self):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        token = [
            ["JWT1", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            json_data["authorization-rules"]["detached-claims"]["x-nv-test"] = True
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(validate_token("http//test", token, remote_att_result_policy))

    def test_validate_claims_fails_with_unknown_claim_in_overall_policy(self):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        token = [
            ["JWT1", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            json_data["authorization-rules"]["overall-claims"]["x-nv-test"] = True
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(validate_token("http//test", token, remote_att_result_policy))