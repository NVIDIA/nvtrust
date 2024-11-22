import json
import os
from unittest import TestCase
from unittest.mock import patch

import pytest
import jwt
from nv_attestation_sdk.gpu import attest_gpu_local
from nv_attestation_sdk import attestation
from nv_attestation_sdk.attestation import Devices, Environment, Attestation

policy_file_path = "../../policies/local/NVGPULocalPolicyExample.json"
overall_claims_file_path = "tests/pytests/data/gpu/overall_claims_local.json"
detached_claims_file_path = "tests/pytests/data/gpu/detached_claims_local.json"
gpu_evidence_list = [{"certificate": "test_cert_chain", "evidence": "test_hex_str"}]


class AttestationGPUTestLocal(TestCase):

    @patch("verifier.cc_admin.attest")
    def test_gpu_local_attest(self, cc_admin):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        cc_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"GPU-0", detached_jwt_token},
        ]
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_gpu_local.attest(nonce, gpu_evidence_list)
        self.assertTrue(result)

    @patch("verifier.cc_admin.collect_gpu_evidence_local")
    def test_gpu_local_get_evidence(self, cc_admin):
        ppcie_mode = True
        cc_admin.return_value = gpu_evidence_list
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        evidence_list = attest_gpu_local.get_evidence(nonce, ppcie_mode)
        self.assertEqual(len(evidence_list), 1)

    @patch("verifier.cc_admin.collect_gpu_evidence_local")
    def test_gpu_local_get_evidence_fails_due_to_driver_error(self, cc_admin):
        ppcie_mode = True
        cc_admin.side_effect = Exception("Driver installation error")
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        evidence_list = attest_gpu_local.get_evidence(nonce, ppcie_mode)
        self.assertEqual(len(evidence_list), 0)

    @patch("verifier.cc_admin.attest")
    def test_gpu_local_attest_fails(self, cc_admin):
        cc_admin.side_effect = Exception("Error in GPU attestation due to driver error")
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_gpu_local.attest(nonce, gpu_evidence_list)
        self.assertFalse(result)
        decoded_jwt_token = jwt.decode(jwt_token, "secret", "HS256")
        self.assertTrue(
            decoded_jwt_token.get("x-nv-err-message") == "GPU_ATTESTATION_ERR"
        )
        self.assertTrue(decoded_jwt_token.get("x-nv-err-code") == 1)

    @patch("verifier.cc_admin.attest")
    def test_validate_gpu_token_when_attestation_passes(self, cc_admin):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        cc_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        client = attestation.Attestation("test-name")
        client.add_verifier(Devices.GPU, Environment.LOCAL, "", "evidence")
        result = client.attest(gpu_evidence_list)
        with open(
            os.path.join(os.path.dirname(__file__), policy_file_path)
        ) as json_file:
            json_data = json.load(json_file)
            att_result_policy = json.dumps(json_data)
        validation_result = client.validate_token(att_result_policy)
        self.assertTrue(validation_result)
        self.assertTrue(result)

    @patch("verifier.cc_admin.attest")
    def test_validate_gpu_token_when_attestation_fails_due_to_measurement_mismatch(
        self, cc_admin
    ):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["measres"] = "fail"
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        cc_admin.return_value = False, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        client = attestation.Attestation("test-name")
        client.add_verifier(Devices.GPU, Environment.LOCAL, "", "evidence")
        result = client.attest(gpu_evidence_list)
        with open(
            os.path.join(os.path.dirname(__file__), policy_file_path)
        ) as json_file:
            json_data = json.load(json_file)
            att_result_policy = json.dumps(json_data)
        validation_result = client.validate_token(att_result_policy)
        self.assertFalse(validation_result)
        self.assertFalse(result)

    @patch("verifier.cc_admin.attest")
    def test_validate_gpu_token_when_attestation_fails_due_to_measurement_mismatch(
        self, cc_admin
    ):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["x-nvidia-gpu-driver-rim-fetched"] = False
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        cc_admin.return_value = False, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        client = attestation.Attestation("test-name")
        client.add_verifier(Devices.GPU, Environment.LOCAL, "", "evidence")
        result = client.attest(gpu_evidence_list)
        with open(
            os.path.join(os.path.dirname(__file__), policy_file_path)
        ) as json_file:
            json_data = json.load(json_file)
            att_result_policy = json.dumps(json_data)
        validation_result = client.validate_token(att_result_policy)
        self.assertFalse(validation_result)
        self.assertFalse(result)

    def test_get_err_eat_token(self):
        jwt_token = attest_gpu_local.get_err_eat_token()
        self.assertTrue(type(jwt_token) is str)
        jwt_decoded = jwt.decode(jwt_token, "secret", "HS256")
        self.assertTrue(jwt_decoded.get("x-nv-err-message") == "GPU_ATTESTATION_ERR")

    @pytest.fixture(autouse=True)
    def reset(self):
        yield
        Attestation.reset()
