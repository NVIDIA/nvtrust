import base64
import json
import unittest
from unittest import mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import jwt
import os
from nv_attestation_sdk.utils.nras_utils import decode_nras_token, validate_gpu_token_with_policy
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime

from nv_attestation_sdk.utils import claim_utils

overall_claims_file_path = "tests/pytests/data/gpu/overall_claims_remote.json"
detached_claims_file_path = "tests/pytests/data/gpu/detached_claims_remote.json"
remote_gpu_policy_file = "../../policies/remote/v3/NVGPURemotePolicyExample.json"

class NrasUtilsTest(unittest.TestCase):

    def setUp(self):
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

    @mock.patch("requests.get")
    def test_decode_nras_token(self, mock_get):
        header = {"kid": "nv-eat-kid-test-1234"}

        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        mock_get.return_value = mock_response
        decoded_token = decode_nras_token("http://test", encoded_jwt)
        self.assertIsNotNone(decoded_token)
        self.assertTrue(decoded_token["x-nvidia-overall-att-result"])
        self.assertEqual(
            decoded_token["eat_nonce"],
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        )

    @mock.patch("requests.get")
    def test_decode_nras_token_failed_no_matching_key_found(self, mock_get):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )

        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234", "x5c": [base64_cert]}]
        }
        mock_get.return_value = mock_response
        decoded_token = decode_nras_token("http://test", encoded_jwt)
        self.assertEqual(decoded_token, {})

    @mock.patch("requests.get")
    def test_decode_nras_token_failed_when_jwks_endpoint_failed(self, mock_get):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        mock_response = mock.Mock()
        mock_response.json.return_value = {"response": "Internal Server Error"}
        mock_get.return_value = mock_response
        decoded_token = decode_nras_token("http://test", encoded_jwt)
        self.assertEqual(decoded_token, {})

    @mock.patch("requests.get")
    def test_decode_nras_token_failed_when_jwt_expires(self, mock_get):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            overall_claims["exp"] = datetime.datetime.utcnow() - datetime.timedelta(
                days=1
            )
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        mock_response = mock.Mock()
        mock_get.return_value = mock_response
        decoded_token = decode_nras_token("http://test", encoded_jwt)
        self.assertEqual(decoded_token, {})

    def test_validate_gpu_token_with_policy_fails_with_invalid_jwt_type(self):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        token = [["JWT1", encoded_jwt], {"GPU-0", detached_jwt}]
        with open(
            os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(validate_gpu_token_with_policy("https://test", token, claim_utils.get_auth_rules(remote_att_result_policy)))

    @mock.patch("requests.get")
    def test_validate_gpu_token_with_policy(self, mock_jwks_request):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")

        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234567", "x5c": [base64_cert]}]
        }
        mock_jwks_request.return_value = mock_response
        token = [["JWT", encoded_jwt], {"GPU-0": detached_jwt}]
        with open(
            os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            remote_att_result_policy = json.dumps(json_data)
        self.assertTrue(validate_gpu_token_with_policy("https://test", token, claim_utils.get_auth_rules(remote_att_result_policy)))

    @mock.patch("requests.get")
    def test_validate_gpu_token_with_policy_with_unknown_overall_claim_in_policy(self, mock_jwks_request):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")

        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234567", "x5c": [base64_cert]}]
        }
        mock_jwks_request.return_value = mock_response
        token = [["JWT", encoded_jwt], {"GPU-0": detached_jwt}]
        with open(
                os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            json_data["authorization-rules"]["overall-claims"]["x-nv-test"] = True
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(
            validate_gpu_token_with_policy("https://test", token, claim_utils.get_auth_rules(remote_att_result_policy)))

    @mock.patch("requests.get")
    def test_validate_gpu_token_with_policy_with_unknown_detached_claim_in_policy(self, mock_jwks_request):
        header = {"kid": "nv-eat-kid-test-1234567"}
        with open(overall_claims_file_path, "r") as file:
            overall_claims = json.load(file)
            encoded_jwt = jwt.encode(
                overall_claims, self.private_pem, algorithm="ES384", headers=header
            )
        with open(detached_claims_file_path, "r") as file:
            detached_claims = json.load(file)
            detached_jwt = jwt.encode(
                detached_claims, self.private_pem, algorithm="ES384", headers=header
            )
        encoded_cert = self.cert.public_bytes(serialization.Encoding.DER)
        base64_cert = base64.b64encode(encoded_cert).decode("utf-8")

        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "keys": [{"kid": "nv-eat-kid-test-1234567", "x5c": [base64_cert]}]
        }
        mock_jwks_request.return_value = mock_response
        token = [["JWT", encoded_jwt], {"GPU-0": detached_jwt}]
        with open(
                os.path.join(os.path.dirname(__file__), remote_gpu_policy_file)
        ) as json_file:
            json_data = json.load(json_file)
            json_data["authorization-rules"]["detached-claims"]["x-nv-test"] = True
            remote_att_result_policy = json.dumps(json_data)
        self.assertFalse(
            validate_gpu_token_with_policy("https://test", token, claim_utils.get_auth_rules(remote_att_result_policy)))