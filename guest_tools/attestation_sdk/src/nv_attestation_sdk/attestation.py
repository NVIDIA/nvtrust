#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
"""
This module provides the Attestation class for handling device attestation.
"""
from datetime import datetime, timedelta
from enum import IntEnum, IntFlag
import json
import logging
import secrets
import uuid

import jwt

from nv_attestation_sdk.utils.logging_config import setup_logging, get_logger
from .gpu import attest_gpu_local, attest_gpu_remote
from .nvswitch import attest_nvswitch_local, attest_nvswitch_remote
from .utils import claim_utils, local_utils, nras_utils
from typing import Tuple, List

decorative_logger = setup_logging()
logger = get_logger()


class Devices(IntFlag):
    """
    An enumeration representing different types of devices that can be attested.

    Attributes:
    CPU: Represents a Central Processing Unit.
    GPU: Represents a Graphics Processing Unit.
    SWITCH: Represents a Network Switch.
    OS: Represents an Operating System.
    DPU: Represents a DPU.
    """

    CPU = 1
    GPU = 2
    SWITCH = 4
    OS = 8
    DPU = 16


class Environment(IntEnum):
    """
    An enumeration representing different environments for attestation.

    Attributes:
    TEST: Represents a testing environment.
    LOCAL: Represents a local environment.
    AZURE: Represents an Azure environment.
    GCP: Represents a Google Cloud Platform environment.
    REMOTE: Represents a remote environment.
    """

    TEST = 1
    LOCAL = 2
    AZURE = 3
    GCP = 4
    REMOTE = 5


class VerifierFields(IntEnum):
    """
    An enumeration representing different fields in a verifier configuration.

    Attributes:
    NAME: Represents the name of the verifier.
    DEVICE: Represents the type of device to be attested.
    ENVIRONMENT: Represents the environment for attestation.
    URL: Represents the URL of the attestation server for remote attestation.
    POLICY: Represents the attestation evidence policy.
    JWT_TOKEN: Represents the JWT token generated during attestation.
    """

    NAME = 0
    DEVICE = 1
    ENVIRONMENT = 2
    URL = 3
    POLICY = 4
    JWT_TOKEN = 5


class Attestation:
    """
    Attestation class for handling device attestation.
    """

    _staticNonce = None
    _name = None
    _nonceServer = None
    _tokens = None
    _verifiers = []
    _instance = None

    def __new__(cls, name=None):
        if cls._instance is None:
            cls._instance = super(Attestation, cls).__new__(cls)
            cls._name = name if isinstance(name, str) else ""
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
    def add_verifier(
        cls, dev: Devices, env: Environment, url: str, evidence: str
    ) -> None:
        """Add a new verifier for Attestation

        Args:
            dev (Devices): Type of device to be attested - GPU, CPU etc.
            env (Environment): Type of Attestation - local, remote etc.
            url (str): URL of the Attestation Server for Remote Attestation use cases.
            evidence (str): Attestation evidence
        """
        verifier_name_mapping = {
            (Devices.GPU, Environment.LOCAL): "LOCAL_GPU_CLAIMS",
            (Devices.GPU, Environment.REMOTE): "REMOTE_GPU_CLAIMS",
            (Devices.SWITCH, Environment.LOCAL): "LOCAL_SWITCH_CLAIMS",
            (Devices.SWITCH, Environment.REMOTE): "REMOTE_SWITCH_CLAIMS",
            (Devices.CPU, Environment.TEST): "TEST_CPU_CLAIMS",
        }

        name = verifier_name_mapping.get((dev, env), "UNKNOWN_CLAIMS")

        lst = [name, dev, env, url, evidence, ""]
        cls._verifiers.append(lst)

    @classmethod
    def clear_verifiers(cls):
        """
        A method to clear the list of verifiers.
        """
        cls._verifiers.clear()

    @classmethod
    def get_verifiers(cls) -> list:
        """Get a list of configured verifiers

        Returns:
            list: List of verifiers
        """
        return cls._verifiers

    @classmethod
    def get_evidence(cls, ppcie_mode: bool = True) -> Tuple[str, List]:
        """
        A class method to get evidence for attestation. Returns evidence for the specified verifier.
        """
        decorative_logger.info("Attestation SDK: Getting Evidence")
        nonce = cls.get_nonce() or cls._generate_nonce()
        logger.info("Nonce generated: %s", nonce)

        evidence_mapping = {
            (Devices.GPU, Environment.LOCAL): attest_gpu_local.get_evidence,
            (Devices.GPU, Environment.REMOTE): attest_gpu_remote.get_evidence,
            (Devices.SWITCH, Environment.LOCAL): attest_nvswitch_local.get_evidence,
            (Devices.SWITCH, Environment.REMOTE): attest_nvswitch_remote.get_evidence,
        }

        for verifier in cls._verifiers:
            device = verifier[VerifierFields.DEVICE]
            environment = verifier[VerifierFields.ENVIRONMENT]
            evidence_func = evidence_mapping.get(
                (device, environment), cls._unknown_verifier
            )
            return evidence_func(nonce, ppcie_mode)

        logger.error("Unknown verifier - Assuming all is good")
        return nonce, []

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
            logger.info("Evidence is empty.. skipping attestation..")
            return False

        attestation_mapping = {
            (Devices.GPU, Environment.LOCAL): attest_gpu_local.attest,
            (Devices.GPU, Environment.REMOTE): attest_gpu_remote.attest,
            (Devices.SWITCH, Environment.LOCAL): attest_nvswitch_local.attest,
            (Devices.SWITCH, Environment.REMOTE): attest_nvswitch_remote.attest
        }

        for verifier in cls._verifiers:
            device = verifier[VerifierFields.DEVICE]
            environment = verifier[VerifierFields.ENVIRONMENT]
            verifier_url = (
                verifier[VerifierFields.URL]
                if environment == Environment.REMOTE
                else None
            )
            attestation_func = attestation_mapping.get(
                (device, environment), cls._unknown_verifier
            )
            if environment == Environment.REMOTE:
                this_result, jwt_token = attestation_func(
                    nonce, evidence_list, verifier_url
                )
            else:
                this_result, jwt_token = attestation_func(
                    nonce, evidence_list
                )
            verifier[VerifierFields.JWT_TOKEN] = jwt_token
            attest_result = attest_result and this_result

        eat_token = cls._create_eat()
        cls.set_token(cls._name, eat_token)
        return attest_result

    @classmethod
    def _unknown_verifier(cls, arg1, arg2):
        """
        Unknown verifier identified. Log the error and return True.
        """
        logger.error("Unknown verifier - Assuming all is good")
        return False, []

    @classmethod
    def _generate_jwt(cls) -> str:
        """
        Generate a JWT token with specific claims and return it as a string.
        """
        issuer = "NV-Attestation-SDK"
        nbf = datetime.utcnow() - timedelta(seconds=120)
        exp = datetime.utcnow() + timedelta(hours=1)
        iat = datetime.utcnow()
        jti = str(uuid.uuid4())

        payload = {"iss": issuer, "iat": iat, "exp": exp, "nbf": nbf, "jti": jti}
        encoded_jwt = jwt.encode(payload, "notasecret", algorithm="HS256")
        return encoded_jwt

    @classmethod
    def _create_verifier_claims(cls) -> dict:
        """
        A method to create verifier claims
        """
        verifier_claims = {}
        for verifier in cls._verifiers:
            if verifier[VerifierFields.JWT_TOKEN] != "":
                verifier_claims[verifier[VerifierFields.NAME]] = verifier[
                    VerifierFields.JWT_TOKEN
                ]
        return verifier_claims

    @classmethod
    def _create_eat(cls) -> str:
        """
        What is an EAT?

        An EAT (Entity Attestation Token) is a list with two elements, A and B:

        - Element A is a list where the first element is "JWT"
        and the second element is a JWT Token.
        - Element B is a dictionary of claims where each element is
        indexed by a name and the value is a JWT Token of the claims
        attested for said name.

        This is what the specification suggests. However, JWT has a
        different idea and wants just a dictionary object.

        Therefore, a JSON-encoded Detached EAT bundle is defined as:

        {
          "JWT" : JWT of main claims,
          "verifier name" : JWT of this verifier
        }

        The "verifier name" is optional and there can be zero or more of them.
        """
        encoded_jwt = cls._generate_jwt()
        verifier_claims = cls._create_verifier_claims()

        eat = []
        eat_inner = ["JWT", encoded_jwt]
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
        name = cls.get_name() if x is None else x if isinstance(x, str) else ""
        return "" if name == "" else cls._tokens.get(name, "")

    @classmethod
    def decode_token(cls, token):
        """
        Decode the EAT token and print the claims
        """
        if token == "":
            logger.info("Token is empty")
            return
        json_array = json.loads(token)
        if len(json_array) >= 2:
            for key, value in json_array[1].items():
                logger.debug("Verifier: %s", key)
                for item in value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            payload = claim_utils.decode_jwt(v)
                            logger.debug("Claim Decoded for : %s", str(k))
                            logger.debug(json.dumps(payload, indent=3))

    @classmethod
    def _validate_token_internal(cls, policy: str, eat_token: str) -> bool:
        """Validate EAT token using the policy

        Args:
            policy (str): Appraisal policy for Attestation results
            eat_token (str): EAT token

        Returns:
            bool: result
        """
        if eat_token == "":
            return False

        try:
            eat = json.loads(eat_token)
        except json.decoder.JSONDecodeError:
            return False

        eat_claims = eat[1]

        if len(eat_claims) == 0:
            return False

        validation_mapping = {
            "LOCAL_GPU_CLAIMS": local_utils.validate_token,
            "LOCAL_SWITCH_CLAIMS": local_utils.validate_token,
            "REMOTE_GPU_CLAIMS": nras_utils.validate_gpu_token,
            "REMOTE_SWITCH_CLAIMS": nras_utils.validate_gpu_token
        }

        attest_result = True
        for verifier_name, jwt_token in eat_claims.items():
            verifier = cls.get_verifier_by_name(verifier_name)
            if verifier is None:
                logger.error("Unknown verifier: %s", verifier_name)
                return False
            validation_func = validation_mapping.get(
                verifier_name)
            this_result = validation_func(verifier, jwt_token, policy)
            attest_result = attest_result and this_result

        return attest_result

    @classmethod
    def get_verifier_by_name(cls, verifier_name):
        """
        Get the verifier by name from the list of verifiers.
        """
        return next(
            (
                verifier
                for verifier in cls._verifiers
                if verifier[VerifierFields.NAME] == verifier_name
            ),
            None,
        )

    @classmethod
    def validate_token(cls, policy: str, x=None):
        """
        Validates the EAT token using the provided appraisal policy.
        """
        decorative_logger.info(
            "Attestation SDK: Validating Evidence using Appraisal Policy"
        )

        if isinstance(x, str) and x:
            return cls._validate_token_internal(policy, x)

        if isinstance(x, dict):
            return {
                name: cls._validate_token_internal(policy, token) if token else False
                for name, token in x.items()
                if name
            }

        if x is None:
            name = cls.get_name()
            token = cls._tokens.get(name, "")
            return cls._validate_token_internal(policy, token) if token else False
        return False

    @classmethod
    def _generate_nonce(cls) -> str:
        """
        Generate a random nonce.
        """
        random_bytes = secrets.token_bytes(32)
        cls.set_nonce(random_bytes.hex())
        return cls.get_nonce()

    @classmethod
    def get_nonce(cls) -> str:
        """
        A method to get the nonce value.
        """
        return cls._staticNonce

    @classmethod
    def set_nonce(cls, nonce: str):
        """
        Set the nonce for the class.

        Parameters:
            nonce (str): The nonce to be set.

        Returns:
            None
        """
        cls._staticNonce = nonce


    @classmethod
    def reset(cls):
        cls._nonceServer = ""
        cls._staticNonce = ""
        cls._verifiers = []
        cls._tokens = {}
