#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
import uuid
from enum import IntFlag
from enum import IntEnum
from datetime import datetime, timedelta
from typing import Tuple, List


from .gpu import attest_gpu_local, attest_gpu_remote, attest_gpu
from nv_attestation_sdk.utils.logging_config import setup_logging

from .nvswitch import attest_nvswitch, attest_nvswitch_local, attest_nvswitch_remote
from .utils import nras_utils, local_utils, claim_utils
import secrets
import jwt
import json
import logging

decorative_logger = setup_logging()
console_logger = logging.getLogger("sdk-console")
file_logger = logging.getLogger("sdk-file")


class Devices(IntFlag):
    CPU = 1
    GPU = 2
    SWITCH = 4
    OS = 8
    DPU = 16


class Environment(IntEnum):
    TEST = 1
    LOCAL = 2
    AZURE = 3
    GCP = 4
    REMOTE = 5


class VerifierFields(IntEnum):
    NAME = 0
    DEVICE = 1
    ENVIRONMENT = 2
    URL = 3
    POLICY = 4
    JWT_TOKEN = 5


class Attestation(object):
    _staticNonce = None
    _name = None
    _nonceServer = None
    _tokens = None
    _verifiers = None
    _instance = None

    def __new__(cls, name=None):
        if cls._instance is None:
            cls._instance = super(Attestation, cls).__new__(cls)
            if isinstance(name, str):
                cls._name = name
            else:
                cls._name = ""
            cls._nonceServer = ""
            cls._staticNonce = ""
            cls._verifiers = []
            cls._tokens = {}
        return cls._instance

    @classmethod
    def set_name(cls, name: str) -> None:
        """Set the name of the Attestation client

        Args:
            name (str): Attestation client name
        """
        cls._name = name

    @classmethod
    def get_name(cls) -> str:
        """Get the name of the Attestation client

        Returns:
            str: Attestation client name
        """
        return cls._name

    @classmethod
    def set_nonce_server(cls, url: str) -> None:
        """Set nonce server URL (not used yet)

        Args:
            url (str): URL of the nonce server
        """
        cls._nonceServer = url

    @classmethod
    def get_nonce_server(cls) -> str:
        """Get the nonce Server URL

        Returns:
            str: URL of the nonce server
        """
        return cls._nonceServer

    @classmethod
    def add_verifier(cls, dev: Devices, env: Environment, url: str, evidence: str) -> None:
        """Add a new verifier for Attestation

        Args:
            dev (Devices): Type of device to be attested - GPU, CPU etc.
            env (Environment): Type of Attestation - local, remote etc.
            url (str): URL of the Attestation Server for Remote Attestation use cases.
            evidence (str): Attestation evidence
        """
        if dev == Devices.GPU and env == Environment.LOCAL:
            name = "LOCAL_GPU_CLAIMS"
        elif dev == Devices.GPU and env == Environment.REMOTE:
            name = "REMOTE_GPU_CLAIMS"
        elif dev == Devices.SWITCH and env == Environment.LOCAL:
            name = "LOCAL_SWITCH_CLAIMS"
        elif dev == Devices.SWITCH and env == Environment.REMOTE:
            name = "REMOTE_SWITCH_CLAIMS"
        elif dev == Devices.CPU and env == Environment.TEST:
            name = "TEST_CPU_CLAIMS"
        else:
            name = "UNKNOWN_CLAIMS"

        lst = [name, dev, env, url, evidence, ""]
        cls._verifiers.append(lst)

    def clear_verifiers(cls):
        cls._verifiers.clear()

    @classmethod
    def get_verifiers(cls) -> list:
        """Get a list of configured verifiers

        Returns:
            list: List of verifiers
        """
        return cls._verifiers

    @classmethod
    def get_evidence(cls) -> Tuple[str, List]:
        # generate nonce if not specified
        decorative_logger.info("Attestation SDK: Getting Evidence")
        nonce = cls.get_nonce()
        if not cls.get_nonce():
            nonce = cls._generate_nonce()
            console_logger.info("Generating nonce .. " + nonce)

        for verifier in cls._verifiers:
            device = verifier[VerifierFields.DEVICE]
            environment = verifier[VerifierFields.ENVIRONMENT]

            if device == Devices.GPU:
                if environment == Environment.LOCAL:
                    return attest_gpu_local.get_evidence(nonce)
                elif environment == Environment.REMOTE:
                    return attest_gpu_remote.get_evidence(nonce)
                else:
                    console_logger.info(
                        "Unknown verifier - Assuming all is good - device is " + str(device) + " env is " + str(
                            environment))
                return attest_gpu.get_evidence(nonce)
            elif device == Devices.SWITCH:
                if environment == Environment.LOCAL:
                    return attest_nvswitch.get_evidence(nonce)
                elif environment == Environment.REMOTE:
                    return attest_nvswitch_remote.get_evidence(nonce)
            else:
                # Throw an exception or handle the unknown case accordingly
                console_logger.error(
                    "Unknown verifier - Assuming all is good - device is " + str(device) + " env is " + str(
                        environment))
        return

    @classmethod
    def attest(cls, evidence_list) -> bool:
        """Attest the client as per the configured verifiers and evidence policy

        Returns:
            bool: Attestation Result
        """
        decorative_logger.info("Attestation SDK: Attesting Device")
        nonce = cls.get_nonce()
        attest_result = True
        if len(evidence_list) == 0:
            console_logger.info("Evidence is empty.. skipping attestation..")
            return False
        for verifier in cls._verifiers:
            device = verifier[VerifierFields.DEVICE]
            environment = verifier[VerifierFields.ENVIRONMENT]
            if device == Devices.GPU:
                if environment == Environment.LOCAL or environment == Environment.REMOTE:
                    verifier_url = verifier[VerifierFields.URL] if environment == Environment.REMOTE else None
                    this_result, jwt_token = attest_gpu_remote.attest(nonce, evidence_list,
                                                                      verifier_url) \
                        if environment == Environment.REMOTE else attest_gpu_local.attest(nonce, evidence_list)
                    verifier[VerifierFields.JWT_TOKEN] = jwt_token
                    attest_result = attest_result and this_result
                else:
                    console_logger.info("Unsupported Attestation Type..")
                    return False
            elif device == Devices.SWITCH:
                if environment == Environment.LOCAL or environment == Environment.REMOTE:
                    verifier_url = verifier[VerifierFields.URL] if environment == Environment.REMOTE else None
                    this_result, jwt_token = attest_nvswitch_remote.attest(nonce, evidence_list, verifier_url) \
                        if environment == Environment.REMOTE else attest_nvswitch_local.attest(nonce, evidence_list)
                    verifier[VerifierFields.JWT_TOKEN] = jwt_token
                    attest_result = attest_result and this_result
                else:
                    console_logger.error("Unsupported Attestation Type..")
                    return False
            elif device == Devices.CPU and environment == Environment.TEST:
                report = {"rand": secrets.token_hex(16)}
                report["hash"] = str(hash(report["rand"]))
                jwt_token = jwt.encode(report, "notasecret", algorithm="HS256")
                verifier[VerifierFields.JWT_TOKEN] = jwt_token
                attest_result = attest_result and True
            else:
                # Throw an exception or handle the unknown case accordingly
                console_logger.error(
                    "Unknown verifier - Assuming all is good - device is " + str(device) + " env is " + str(
                        environment))
        # NOTE: no verifiers means attestation will be true.  weird but makes some sense
        # NOTE: THIS is where the tokens should be combined in to a single token and then set
        eatToken = cls._create_EAT()
        cls.set_token(cls._name, eatToken)
        return attest_result

    @classmethod
    def _create_EAT(cls) -> str:
        #
        # What is an EAT
        #
        # An EAT is a list with two elements let's call them A and B
        # element A is a list where the first element is "JWT" and the second element is a JWT Token
        # element B is a dictionary of claims where each element is indexed by a name and the value
        #           is a JWT Token of the claims attested for said name
        # or at least that is what the spec suggests
        # JWT has a very different idea and wants just a dictionary object.
        #
        # Therefore a JSON-encoded Detached EAT bundle is defined as
        # {
        #   "JWT" : JWT of main claims
        # zero or more of the following
        #   "verifier name" : JWT of this verifier
        # }
        issuer = "NV-Attestation-SDK"

        nbf = datetime.utcnow() - timedelta(seconds=120)
        exp = datetime.utcnow() + timedelta(hours=1)
        iat = datetime.utcnow()
        jti = str(uuid.uuid4())

        payload = {"iss": issuer, "iat": iat, "exp": exp, "nbf": nbf, "jti": jti}
        encoded_jwt = jwt.encode(payload, "notasecret", algorithm="HS256")

        eat = []
        eat_inner = ["JWT", encoded_jwt]
        verifier_claims = {}

        for verifier in cls._verifiers:
            if verifier[VerifierFields.JWT_TOKEN] != "":
                verifier_claims[verifier[VerifierFields.NAME]] = verifier[VerifierFields.JWT_TOKEN]

        eat.append(eat_inner)
        eat.append(verifier_claims)
        return json.dumps(eat)

    @classmethod
    def set_token(cls, name: str, eat_token: str) -> None:
        """Set result EAT token for a client

        Args:
            name (str): Attestation Client name
            eat_token (str): EAT token
        """
        entry = {name: eat_token}
        cls._tokens.update(entry)

    @classmethod
    def get_token(cls, x=None) -> str:
        """Get the Attestation EAT token for a client

        Args:
            x (_type_, optional): Client name. Defaults to None.

        Returns:
            str: EAT token in string format
        """
        name = ""
        if x == None:
            name = cls.get_name()
        elif isinstance(x, str):
            name = x

        if name == "":
            return ""

        if name in cls._tokens.keys():
            return cls._tokens[name]
        else:
            return ""

    @classmethod
    def decode_token(cls, token):
        json_array = json.loads(token)
        if len(json_array) >= 2:
            for key, value in json_array[1].items():
                for item in value:
                    if type(item) is dict:
                        for k, v in item.items():
                            payload = claim_utils.decode_jwt(v)
                            file_logger.info("Claim Decoded for :" + str(k))
                            file_logger.info(json.dumps(payload, indent=3))

    @classmethod
    def _validate_token_internal(cls, policy: str, eat_token: str) -> bool:
        """Validate a EAT token using the policy

        Args:
            policy (str): Appraisal policy for Attestation results
            eat_token (str): EAT token

        Returns:
            bool: result
        """
        attest_result = True

        if eat_token == "":
            return False
        else:

            try:
                eat = json.loads(eat_token)
            except json.decoder.JSONDecodeError:
                return False

            eat_jwt = eat[0]
            eat_claims = eat[1]

            if len(eat_claims) == 0:
                return False

            for verifier_name in eat_claims:
                jwt_token = eat_claims[verifier_name]
                verifier = cls.get_verifier_by_name(verifier_name)
                if verifier_name == "LOCAL_GPU_CLAIMS" or verifier_name == "LOCAL_SWITCH_CLAIMS":
                    this_result = local_utils.validate_token(jwt_token, policy)
                elif verifier_name == "REMOTE_GPU_CLAIMS" or verifier_name == "REMOTE_SWITCH_CLAIMS":
                    this_result = nras_utils.validate_gpu_token(verifier, jwt_token, policy)
                elif verifier_name == "TEST_CPU_CLAIMS":
                    claims = jwt.decode(jwt_token, "notasecret", algorithms="HS256")

                    randStr = claims["rand"]
                    hashStr = claims["hash"]

                    if hashStr == str(hash(randStr)):
                        this_result = True
                    else:
                        this_result = False

                else:
                    #Unknown verifier - assume it's OK
                    console_logger.error("unknown verifier..")
                    this_result = True

                attest_result = this_result and attest_result

        return attest_result

    @classmethod
    def get_verifier_by_name(cls, verifier_name):
        for verifier in cls._verifiers:
            if verifier[VerifierFields.NAME] == verifier_name:
                return verifier
        return None

    @classmethod
    def validate_token(cls, policy: str, x=None):
        decorative_logger.info("Attestation SDK: Validating Evidence using Appraisal Policy")
        if x == None:
            name = cls.get_name()
            if name == "":
                return False
            else:
                if name in cls._tokens.keys():
                    token = cls._tokens[name]
                else:
                    return False

                return cls._validate_token_internal(policy, token)

        elif isinstance(x, str):
            if x == "":
                return False
            else:
                return cls._validate_token_internal(policy, x)

        elif isinstance(x, list):
            return False

        # this part could use some bullet proofing
        elif isinstance(x, dict):
            ret_dict = {}
            for name in x:
                if name != "":
                    token = x[name]
                    if token != "":
                        ret_dict[name] = cls._validate_token_internal(token)
                    else:
                        ret_dict[name] = False
            return ret_dict
        else:
            return False

    @classmethod
    def _generate_nonce(cls) -> str:
        random_bytes = secrets.token_bytes(32)
        cls.set_nonce(random_bytes.hex())
        return cls.get_nonce()

    @classmethod
    def get_nonce(cls) -> str:
        return cls._staticNonce

    @classmethod
    def set_nonce(cls, nonce: str):
        cls._staticNonce = nonce
