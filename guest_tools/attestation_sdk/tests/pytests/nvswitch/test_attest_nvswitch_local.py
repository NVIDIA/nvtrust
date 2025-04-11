import json
import os
from unittest import TestCase
from unittest.mock import patch

import pytest
import jwt
from nv_attestation_sdk.nvswitch import attest_nvswitch_local
from nv_attestation_sdk import attestation
from nv_attestation_sdk.attestation import Devices, Environment, Attestation
from nv_attestation_sdk.verifiers.nv_switch_verifier import nvswitch_admin

policy_file_path = "../../policies/local/NVSwitchLocalPolicyExample.json"
overall_claims_file_path = "tests/pytests/data/switch/overall_claims_local.json"
detached_claims_file_path = "tests/pytests/data/switch/detached_claims_local.json"
granular_policy_file_path = "../../policies/local/NVSwitchLocalGranularPolicyExample.json"
overall_granular_claims_file_path = "tests/pytests/data/switch/overall_granular_claims_local.json"
detached_granular_claims_file_path = "tests/pytests/data/switch/detached_granular_claims_local.json"
TEST_CERT_CHAIN = "test_cert_chain"
TEST_HEX_STR = "test_hex_str"
switch_evidence_list = [{"certificate": TEST_CERT_CHAIN, "evidence": TEST_HEX_STR}]


class AttestationTestNvSwitchLocal(TestCase):

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_nvswitch_local_attest(self, nvswitch_admin):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        nvswitch_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0", detached_jwt_token},
        ]
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {})
        self.assertTrue(result)

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_nvswitch_local_attest_with_service_key(self, nvswitch_admin):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        nvswitch_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0", detached_jwt_token},
        ]
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {"service_key": "someServiceKey"})
        self.assertTrue(result)

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_nvswitch_local_attest_with_claims_version_2(self, nvswitch_admin):
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        nvswitch_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0", detached_jwt_token},
        ]
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {"claims_version": "2.0"})
        self.assertTrue(result)

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_nvswitch_local_attest_with_claims_version_3(self, nvswitch_admin):
        with open(overall_granular_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(detached_granular_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        nvswitch_admin.return_value = True, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0", detached_jwt_token},
        ]
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {"claims_version": "3.0"})
        self.assertTrue(result)

    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence"
    )
    def test_switch_local_get_evidence(self, nvswitch_admin):
        nvswitch_admin.return_value = switch_evidence_list
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        evidence_list = attest_nvswitch_local.get_evidence(nonce, { 'ppcie_mode': True })
        self.assertEqual(len(evidence_list), 1)

    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence"
    )
    def test_switch_local_get_evidence_fails_due_to_driver_error(self, nvswitch_admin):
        nvswitch_admin.side_effect = Exception("Driver installation error")
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        evidence_list = attest_nvswitch_local.get_evidence(nonce, { 'ppcie_mode': True })
        self.assertEqual(len(evidence_list), 0)

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_switch_local_attest_fails(self, nvswitch_admin):
        nvswitch_admin.side_effect = Exception(
            "Error in Switch attestation due to driver error"
        )
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {})
        self.assertFalse(result)
        decoded_jwt_token = jwt.decode(jwt_token, "secret", "HS256")
        self.assertTrue(
            decoded_jwt_token.get("x-nv-err-message") == "NVSWITCH_ATTESTATION_ERR"
        )
        self.assertTrue(decoded_jwt_token.get("x-nv-err-code") == 1)

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    def test_switch_local_attest_with_service_key_fails(self, nvswitch_admin):
        nvswitch_admin.side_effect = Exception(
            "Error in Switch attestation due to driver error"
        )
        nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        result, jwt_token = attest_nvswitch_local.attest(nonce, switch_evidence_list, {"service_key": "someServiceKey"})
        self.assertFalse(result)
        decoded_jwt_token = jwt.decode(jwt_token, "secret", "HS256")
        self.assertTrue(
            decoded_jwt_token.get("x-nv-err-message") == "NVSWITCH_ATTESTATION_ERR"
        )
        self.assertTrue(decoded_jwt_token.get("x-nv-err-code") == 1)

    def test_get_err_eat_token(self):
        jwt_token = attest_nvswitch_local.get_err_eat_token()
        self.assertTrue(type(jwt_token) is str)
        jwt_decoded = jwt.decode(jwt_token, "secret", "HS256")
        self.assertTrue(
            jwt_decoded.get("x-nv-err-message") == "NVSWITCH_ATTESTATION_ERR"
        )

    @pytest.fixture(autouse=True)
    def reset(self):
        yield
        Attestation.reset()
