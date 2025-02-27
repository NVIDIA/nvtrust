import base64
import json
import os
from unittest import TestCase, mock
from unittest.mock import patch, Mock

import jwt
import pytest
import verifier
from nv_attestation_sdk import attestation
import jwt
import datetime
from nv_attestation_sdk.gpu import attest_gpu_remote
from nv_attestation_sdk import attestation
from nv_attestation_sdk.attestation import Devices, Environment, Attestation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import jwt

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from nv_attestation_sdk.attestation import Devices, Environment

from nv_attestation_sdk.attestation import Attestation


local_gpu_policy_file = "../policies/local/NVGPULocalPolicyExample.json"
remote_gpu_policy_file = "../policies/remote/v3/NVGPURemotePolicyExample.json"
local_switch_policy_file = "../policies/local/NVSwitchLocalPolicyExample.json"
remote_switch_policy_file = "../policies/remote/v3/NVSwitchRemotePolicyExample.json"

local_gpu_overall_claims_file_path = "tests/pytests/data/gpu/overall_claims_local.json"
local_gpu_detached_claims_file_path = "tests/pytests/data/gpu/detached_claims_local.json"
remote_gpu_overall_claims_file_path = "tests/pytests/data/gpu/overall_claims_remote.json"
remote_gpu_detached_claims_file_path = "tests/pytests/data/gpu/detached_claims_remote.json"
local_switch_overall_claims_file_path = "tests/pytests/data/switch/overall_claims_local.json"
local_switch_detached_claims_file_path = "tests/pytests/data/switch/detached_claims_local.json"
remote_switch_overall_claims_file_path = "tests/pytests/data/switch/overall_claims_remote.json"
remote_switch_detached_claims_file_path = "tests/pytests/data/switch/detached_claims_remote.json"
evidence_list = [{"certificate": "test_cert_chain", "evidence": "test_hex_str"}]


class AttestationTest(TestCase):

    def test_add_local_gpu_verifier(self):
        Attestation.clear_verifiers()
        dev = Devices.GPU
        env = Environment.LOCAL
        url = ""
        evidence = "test_evidence"

        Attestation.add_verifier(dev, env, url, evidence)

        verifiers = Attestation.get_verifiers()
        assert len(verifiers) == 1
        assert verifiers[0][0] == "LOCAL_GPU_CLAIMS"
        assert verifiers[0][1] == dev
        assert verifiers[0][2] == env
        assert verifiers[0][4] == evidence

    def test_add_remote_gpu_verifier(self):
        Attestation.clear_verifiers()
        dev = Devices.GPU
        env = Environment.REMOTE
        url = "http://localhost:8080"
        evidence = ""

        Attestation.add_verifier(dev, env, url, evidence)

        verifiers = Attestation.get_verifiers()
        assert len(verifiers) == 1
        assert verifiers[0][0] == "REMOTE_GPU_CLAIMS"
        assert verifiers[0][1] == dev
        assert verifiers[0][2] == env
        assert verifiers[0][3] == url
        assert verifiers[0][4] == evidence

    def test_add_remote_switch_verifier(self):
        Attestation.clear_verifiers()
        dev = Devices.SWITCH
        env = Environment.REMOTE
        url = "http://localhost:8080"
        evidence = ""

        Attestation.add_verifier(dev, env, url, evidence)

        verifiers = Attestation.get_verifiers()
        assert len(verifiers) == 1
        assert verifiers[0][0] == "REMOTE_SWITCH_CLAIMS"
        assert verifiers[0][1] == dev
        assert verifiers[0][2] == env
        assert verifiers[0][3] == url
        assert verifiers[0][4] == evidence

    def test_add_local_switch_verifier(self):
        Attestation.clear_verifiers()
        dev = Devices.SWITCH
        env = Environment.LOCAL
        url = ""
        evidence = ""

        Attestation.add_verifier(dev, env, url, evidence)

        verifiers = Attestation.get_verifiers()
        assert len(verifiers) == 1
        assert verifiers[0][0] == "LOCAL_SWITCH_CLAIMS"
        assert verifiers[0][1] == dev
        assert verifiers[0][2] == env
        assert verifiers[0][3] == url
        assert verifiers[0][4] == evidence

    def test_add_unknown_verifier(self):
        Attestation.clear_verifiers()
        dev = Devices.SWITCH
        env = Environment.LOCAL
        url = ""
        evidence = ""

        # Interchanged the values of dev and env to produce an unknown verifier
        Attestation.add_verifier(env, dev, url, evidence)
        verifiers = Attestation.get_verifiers()
        assert verifiers[0][0] == "UNKNOWN_CLAIMS"

    def test_add_multiple_verifiers(self):
        Attestation.clear_verifiers()
        dev = Devices.SWITCH
        env = Environment.LOCAL
        url = ""
        evidence = ""

        Attestation.add_verifier(Devices.SWITCH, env, url, evidence)
        Attestation.add_verifier(Devices.GPU, env, url, evidence)

        verifiers = Attestation.get_verifiers()
        assert len(verifiers) == 2
        assert verifiers[0][0] == "LOCAL_SWITCH_CLAIMS"
        assert verifiers[0][1] == dev
        assert verifiers[0][2] == env
        assert verifiers[0][3] == url
        assert verifiers[0][4] == evidence
        assert verifiers[1][0] == "LOCAL_GPU_CLAIMS"
        assert verifiers[1][1] == Devices.GPU
        assert verifiers[1][2] == env
        assert verifiers[1][3] == url
        assert verifiers[1][4] == evidence
    def remote_attestation_setup(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

        self.private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            ]
        )
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

    def test_init_attestation(self):
        client = attestation.Attestation("test-name")
        self.assertEqual(client.get_name(), "test-name")

    def test_set_nonce_server(self):
        client = attestation.Attestation("test-name")
        client.set_nonce_server("http://localhost:8080")
        self.assertEqual(client.get_nonce_server(), "http://localhost:8080")

    def test_generate_nonce(self):
        client = attestation.Attestation("test-name")
        client._generate_nonce()
        self.assertIsNot(client.get_nonce(), None)

    def test_set_ocsp_nonce_disabled_raises_error_on_invalid_datatype(self):
        client = attestation.Attestation("test-name")
        with self.assertRaises(ValueError):
            client.set_ocsp_nonce_disabled("somestring")

    def test_set_ocsp_nonce_disabled(self):
        client = attestation.Attestation("test-name")
        client.set_ocsp_nonce_disabled(True)
        ocsp_nonce_disabled = client.get_ocsp_nonce_disabled()
        self.assertEqual(ocsp_nonce_disabled, True)

    def test_validate_token_internal_when_eat_is_empty(self):
        client = attestation.Attestation("test-name")
        self.assertFalse(client._validate_token_internal("policy", ""))

    def test_validate_token_internal_when_eat_is_not_valid(self):
        client = attestation.Attestation("test-name")
        self.assertFalse(client._validate_token_internal("policy", "{}json"))

    def test_validate_token_interval_for_unknown_verifier(self):
        client = attestation.Attestation("test-name")
        token = [
            ["JWT", "token"],
            {"GPU-0": "GPU-0"},
        ]
        client.add_verifier(
            attestation.Environment.LOCAL, attestation.Environment.LOCAL, "", "")
        self.assertFalse(
            client._validate_token_internal(
                "policy", str(token)
            )
        )
        self.assertFalse(client.validate_token("policy"))

    def test_get_verifiers(self):
        client1 = attestation.Attestation("test-name1")
        client1.add_verifier(
            Devices.GPU, Environment.LOCAL, "http://localhost:8080", "evidence"
        )
        verifiers = client1.get_verifiers()
        self.assertEqual(verifiers[0][0], "LOCAL_GPU_CLAIMS")

    def test_set_token(self):
        client = attestation.Attestation("test-name")
        client.set_token("Test", "token")
        self.assertEqual(client.get_token("Test"), "token")

    def test_set_nonce(self):
        client = attestation.Attestation("test-name")
        client.set_nonce("123456")
        self.assertEqual(client.get_nonce(), "123456")

    #
    def test_create_eat(self):
        client = attestation.Attestation("test-name")
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        eat = client._create_eat()
        self.assertTrue(eat)

    def test_attest_with_empty_evidence(self):
        client = attestation.Attestation("test-name1")
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        self.assertFalse(client.attest([]))

    @patch("verifier.cc_admin.collect_gpu_evidence")
    def test_get_evidence_for_local_gpu_attestation(self, gpu_evidence):
        client = attestation.Attestation("test-name1")
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        evidence = client.get_evidence()
        self.assertTrue(evidence)

    @patch("verifier.cc_admin.collect_gpu_evidence_remote")
    def test_get_evidence_for_remote_gpu_attestation(self, collect_gpu_evidence_remote):
        client = attestation.Attestation("test-name1")
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.REMOTE, "", ""
        )
        collect_gpu_evidence_remote.return_value = evidence_list
        evidence = client.get_evidence()
        self.assertTrue(evidence)


    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence"
    )
    def test_get_evidence_for_local_switch_attestation(self, collect_switch_evidence):
        client = attestation.Attestation("test-name1")
        collect_switch_evidence.return_value = evidence_list
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.LOCAL, "", ""
        )
        evidence = client.get_evidence()
        self.assertTrue(evidence)

    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence_remote"
    )
    def test_get_evidence_for_remote_gpu_attestation(self, collect_switch_evidence_remote):
        client = attestation.Attestation("test-name1")
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.REMOTE, "", ""
        )
        collect_switch_evidence_remote.return_value = evidence_list
        evidence = client.get_evidence()
        self.assertTrue(evidence)

    def test_get_empty_evidence_for_unknwon_verifier(self):
        client = attestation.Attestation("test-name1")
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Devices.SWITCH, "", ""
        )
        evidence = client.get_evidence()
        self.assertIsNotNone(evidence[0])
        self.assertEqual(len(evidence[1]), 0)

    @patch("verifier.cc_admin.attest")
    @patch("verifier.cc_admin.collect_gpu_evidence")
    def test_attest_gpu_local_and_token_validation_is_successful(
        self, gpu_evidence, attest
    ):
        client, gpu_evidence_list = self.gpu_attestation_setup(gpu_evidence)
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        with open(local_gpu_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(local_gpu_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        attest.return_value = True, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        self.assertTrue(client.attest(gpu_evidence_list))
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(client.validate_token(remote_att_result_policy))
        client.decode_token(client.get_token())

    @patch("verifier.cc_admin.attest")
    @patch("verifier.cc_admin.collect_gpu_evidence")
    def test_attest_gpu_local_and_token_validation_is_successful(
        self, gpu_evidence, attest
    ):
        client, gpu_evidence_list = self.gpu_attestation_setup(gpu_evidence)
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        with open(local_gpu_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(local_gpu_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        attest.return_value = True, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        self.assertTrue(client.attest(gpu_evidence_list))
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(client.validate_token(remote_att_result_policy))
        client.decode_token(client.get_token())

    def gpu_attestation_setup(self, gpu_evidence):
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")

        gpu_evidence.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        return client, evidence_list

    @patch("verifier.cc_admin.attest")
    @patch("verifier.cc_admin.collect_gpu_evidence")
    def test_attest_gpu_local_and_token_validation_fails_due_to_measurement_mismatch(
        self, gpu_evidence, attest
    ):
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")
        client.add_verifier(
            attestation.Devices.GPU, attestation.Environment.LOCAL, "", ""
        )
        gpu_evidence.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )

        with open(local_gpu_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(local_gpu_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["measres"] = "fail"
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        attest.return_value = False, [
            ["JWT", overall_jwt_token],
            {"GPU-0": detached_jwt_token},
        ]
        self.assertFalse(client.attest(evidence_list))
        with open(
            os.path.join(os.path.dirname(__file__), local_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(client.validate_token(remote_att_result_policy))

    @mock.patch("requests.get")
    @mock.patch("requests.request")
    @patch("verifier.cc_admin.collect_gpu_evidence_remote")
    def test_attest_gpu_remote_and_token_validation_fails_due_to_measurement_mismatch(
        self, gpu_evidence, nras_mock_request, jwks_mock_request
    ):
        self.remote_attestation_setup()
        client1 = attestation.Attestation("test-name2")
        client1.add_verifier(
            attestation.Devices.GPU,
            attestation.Environment.REMOTE,
            "https://test-nras",
            "",
        )
        gpu_evidence.return_value = evidence_list

        header = {"kid": "nv-eat-kid-test-1234"}
        with open(remote_gpu_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_claims_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        with open(remote_gpu_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["measres"] = "fail"
            detached_jwt_token = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        nras_mock_response = mock.Mock()
        nras_mock_response.json.return_value = [
            ["JWT", overall_claims_jwt],
            {"GPU-0": detached_jwt_token},
        ]
        nras_mock_response.status_code = 200
        nras_mock_request.return_value = nras_mock_response
        jwks_mock_response = mock.Mock()
        jwks_mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        jwks_mock_request.return_value = jwks_mock_response

        self.assertFalse(client1.attest(evidence_list))
        with open(
            os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(client1.validate_token(remote_att_result_policy))
        client1.clear_verifiers()

    @mock.patch("requests.get")
    @mock.patch("requests.request")
    @patch("verifier.cc_admin.collect_gpu_evidence_remote")
    def test_attest_gpu_remote_and_token_validation_is_successful(
        self, gpu_evidence, nras_mock_request, jwks_mock_request
    ):
        self.remote_attestation_setup()
        client1 = attestation.Attestation("test-name2")
        client1.add_verifier(
            attestation.Devices.GPU,
            attestation.Environment.REMOTE,
            "https://test-nras",
            "",
        )
        client1.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        gpu_evidence.return_value = evidence_list

        header = {"kid": "nv-eat-kid-test-1234"}
        with open(remote_gpu_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        with open(remote_gpu_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        nras_mock_response = mock.Mock()
        nras_mock_response.json.return_value = [
            ["JWT", overall_claims_jwt],
            {"GPU-0": detached_jwt_token},
        ]
        nras_mock_response.status_code = 200
        nras_mock_request.return_value = nras_mock_response
        jwks_mock_response = mock.Mock()
        jwks_mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        jwks_mock_request.return_value = jwks_mock_response

        self.assertTrue(client1.attest(evidence_list))
        with open(
            os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(client1.validate_token(remote_att_result_policy))
        client1.clear_verifiers()

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence"
    )
    def test_attest_switch_local_and_token_validation_is_successful(
            self, nvswitch_admin, attest
    ):
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")
        nvswitch_admin.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.LOCAL, "", ""
        )
        with open(local_switch_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(local_switch_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        attest.return_value = True, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0": detached_jwt_token},
        ]
        self.assertTrue(client.attest(evidence_list))
        with open(
                os.path.join(os.path.dirname(__file__), local_switch_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(client.validate_token(remote_att_result_policy))

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.attest")
    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence"
    )
    def test_attest_switch_local_and_token_validation_fails_due_to_measurement_mismatch(
            self, nvswitch_admin, attest
    ):
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")
        nvswitch_admin.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.LOCAL, "", ""
        )
        with open(local_switch_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_jwt_token = jwt.encode(overall_claims, "secret", algorithm="HS256")
        with open(local_switch_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["measres"] = "fail"
            detached_jwt_token = jwt.encode(
                detached_claims, "secret", algorithm="HS256"
            )
        attest.return_value = False, [
            ["JWT", overall_jwt_token],
            {"SWITCH-0": detached_jwt_token},
        ]
        self.assertFalse(client.attest(evidence_list))
        with open(
                os.path.join(os.path.dirname(__file__), local_switch_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(client.validate_token(remote_att_result_policy))

    @mock.patch("requests.get")
    @mock.patch("requests.request")
    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence_remote"
    )
    def test_attest_switch_remote_and_token_validation_is_successful(
            self, nvswitch_admin, nras_mock_request, jwks_mock_request
    ):
        self.remote_attestation_setup()
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")
        nvswitch_admin.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.REMOTE, "", ""
        )

        header = {"kid": "nv-eat-kid-test-1234"}
        with open(remote_switch_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        with open(remote_switch_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt_token = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        nras_mock_response = mock.Mock()
        nras_mock_response.json.return_value = [
            ["JWT", overall_claims_jwt],
            {"SWITCH-0": detached_jwt_token},
        ]
        nras_mock_response.status_code = 200
        nras_mock_request.return_value = nras_mock_response
        jwks_mock_response = mock.Mock()
        jwks_mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        jwks_mock_request.return_value = jwks_mock_response
        self.assertTrue(client.attest(evidence_list))
        with open(
                os.path.join(os.path.dirname(__file__), remote_switch_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(client.validate_token(remote_att_result_policy))

    @mock.patch("requests.get")
    @mock.patch("requests.request")
    @patch(
        "nv_attestation_sdk.verifiers.nv_switch_verifier.nvswitch_admin.collect_evidence_remote"
    )
    def test_attest_switch_remote_and_token_validation_fails_due_to_measurement_mismatch(
            self, nvswitch_admin, nras_mock_request, jwks_mock_request
    ):
        self.remote_attestation_setup()
        client = attestation.Attestation("test-name1")
        client.set_name("test-name")
        nvswitch_admin.return_value = evidence_list
        client.set_nonce(
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        )
        client.add_verifier(
            attestation.Devices.SWITCH, attestation.Environment.REMOTE, "", ""
        )

        header = {"kid": "nv-eat-kid-test-1234"}
        with open(remote_switch_overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["x-nvidia-overall-att-result"] = False
            overall_claims_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        with open(remote_switch_detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_claims["measres"] = "fail"
            detached_jwt_token = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        nras_mock_response = mock.Mock()
        nras_mock_response.json.return_value = [
            ["JWT", overall_claims_jwt],
            {"SWITCH-0": detached_jwt_token},
        ]
        nras_mock_response.status_code = 200
        nras_mock_request.return_value = nras_mock_response
        jwks_mock_response = mock.Mock()
        jwks_mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        jwks_mock_request.return_value = jwks_mock_response
        self.assertFalse(client.attest(evidence_list))
        with open(
                os.path.join(os.path.dirname(__file__), remote_switch_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(client.validate_token(remote_att_result_policy))

    @pytest.fixture(autouse=True)
    def reset(self):
        yield
        Attestation.clear_verifiers()
