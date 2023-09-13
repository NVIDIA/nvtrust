#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import json
import jwt
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from nv_attestation_sdk import attestation
from urllib.parse import urlparse

def validate_gpu_token_local(verifier, gpu_token: str, policy: str):
    if policy == "" or gpu_token == "":
        return False
    decoded_token = jwt.decode(gpu_token, algorithms='HS256', verify=False, key="secret")
    auth_rules = get_auth_rules(policy)
    return validate_gpu_token_with_policy(decoded_token, auth_rules)

def validate_gpu_token_with_policy(token: str, policy: str):
    for key in policy:
        if key in token:
            if type(policy[key]) is dict:
                return validate_gpu_token_with_policy(token[key], policy[key])
            else:
                if token[key] != policy[key]:
                    print("\t[ERROR] Invalid token. Authorized claims does not match the appraisal policy: ", key)
                    return False
        else:
            print("\t[ERROR] Invalid token. Authorized claims does not match the appraisal policy: ", key)
            return False
    return True

def get_auth_rules(policy: str):
    if policy == "":
        return None
    policy_obj = json.loads(policy)
    return policy_obj['authorization-rules']

def create_jwks_url(verifier_url:str):
    parsed_url = urlparse(verifier_url)
    jwks_url = parsed_url.scheme + "://" + parsed_url.netloc + "/" + ".well-known/jwks.json"
    return jwks_url

def validate_gpu_token_remote(verifier, gpu_token: str, policy: str):
    verifier_url = verifier[attestation.VerifierFields.URL]
    jwks_url = create_jwks_url(verifier_url)
    print("***** Validating Signature using JWKS endpont " + jwks_url + " ****** ")
    jwks_response = requests.get(jwks_url)
    jwks_data = jwks_response.json()
    header = jwt.get_unverified_header(gpu_token)
    kid = header['kid']
    # Find the key with the matching kid in the JWKS
    matching_key = None
    for key in jwks_data["keys"]:
        if key["kid"] == kid:
            matching_key = key
            break

    if matching_key and "x5c" in matching_key:
        try:
            matching_cert = matching_key["x5c"][0].encode()
            # Convert the base64-encoded X.509 certificate to a certificate object
            cert_bytes = b"".join([b"-----BEGIN CERTIFICATE-----\n",
                                   matching_key["x5c"][1].encode(),
                                   b"\n-----END CERTIFICATE-----\n"])
            dercert = base64.b64decode(matching_cert)
            cert = load_der_x509_certificate(dercert, default_backend())
            # Get the public key in PEM format
            public_key_pem = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # Verify the JWT token signature using the certificate's public key
            # skipping iat and nbf verification until https://github.com/jpadilla/pyjwt/issues/814 is fixed
            decoded_token = jwt.decode(
                gpu_token,
                cert.public_key(),
                algorithms=["ES384"],
                options={'verify_iat': False,'verify_nbf': False}
            )
            json_formatted_str = json.dumps(decoded_token, indent=2)
            print("Decoded Token " , str(json_formatted_str))
            print("***** JWT token signature is valid. *****")
            auth_rules = get_auth_rules(policy)
            return validate_gpu_token_with_policy(decoded_token, auth_rules)
        except jwt.ExpiredSignatureError:
            print("JWT token has expired.")
        except jwt.InvalidTokenError as e:
            print("JWT token signature is invalid.", repr(e ))
    else:
        print("No matching key or x5c key found for the provided kid.")
    return False

def attest_gpu_local(nonce):
    attestation_result = False
    from verifier import cc_admin
    jwt_token = ""
    try:
        params = {"verbose": True,
                  "test_no_gpu": False,
                  "driver_rim": "/usr/share/nvidia/rim/RIM_GH100PROD.swidtag",
                  "vbios_rim": None,
                  "user_mode": True,
                  'nonce': nonce}
        attestation_result, jwt_token = cc_admin.attest(params)
    except Exception as e:
        print("\tException: ", e)
        jwt_token = get_err_eat_token()
    return attestation_result, jwt_token

def attest_gpu_remote(nonce, verifierUrl):
    from verifier import cc_admin
    attestation_result = False
    jwt_token = ""
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        print("attest_gpu_remote")
        gpu_evidence_list = cc_admin.collect_gpu_evidence(nonce)
        for i , gpu_evidence in enumerate(gpu_evidence_list):
            gpu_evidence = gpu_evidence_list[i]
            current_gpu_status = False
            payload = build_payload(nonce, gpu_evidence['attestationReportHexStr'],gpu_evidence['certChainBase64Encoded'])
            print("Calling NRAS to attest GPU evidence...")
            response = requests.request("POST", verifierUrl, headers=headers, data=payload)
            reponse_json = response.json()
            if response.status_code == 200:
                print("**** Attestation Successful ****")
                jwt_token = reponse_json["eat"]
                print("Entity Attestation Token is " + jwt_token)
                current_gpu_status = True
            else:
                print("**** Attestation Failed ****")
                print("received NRAS response code: ", response.status_code)
                #jwt_token = get_err_eat_token(reponse_json['errorCode'], reponse_json['message'])
            if i == 0:
                attestation_result = current_gpu_status
            else:
                attestation_result = overall_status and current_gpu_status
    except Exception as e:
        print("\tException: ", e)
    return attestation_result, jwt_token

def get_err_eat_token(errCode=1, errMsg="GPU_ATTESTATION_ERR"):
    errJson = {'x-nv-err-message': errMsg, 'x-nv-err-code': errCode}
    return jwt.encode(errJson,
                        'secret',
                        "HS256")

def build_payload(nonce, evidence, cert_chain):
    data = dict()
    data['nonce'] = nonce
    encoded_evidence_bytes = evidence.encode("ascii")                                                                                                                                                      
    encoded_evidence = base64.b64encode(encoded_evidence_bytes)                                                                                                                                                 
    encoded_evidence = encoded_evidence.decode('utf-8')       
    data['evidence'] = encoded_evidence
    data['arch'] = 'HOPPER'
    data['certificate'] = str(cert_chain)
    payload = json.dumps(data)
    return payload

