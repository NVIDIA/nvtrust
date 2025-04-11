#
# SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from hashlib import sha384
import os
from enum import Enum
from nv_attestation_sdk.utils.logging_config import get_logger

logger = get_logger()
parent_dir = os.path.dirname(os.path.abspath(__file__))

logger.debug("----------STARTING----------")


class BaseSettings:
    PROJECT = "5612"
    PROJECT_SKU = "0002"
    CHIP_SKU = "890"
    SIZE_OF_NONCE_IN_BYTES = 32
    SIZE_OF_NONCE_IN_HEX_STR = 64
    attestation_report_availability = False
    NONCE = "4cff7f5380ead8fad8ec2c531c110aca4302a88f603792801a8ca29ee151af2e"
    # The Timeout duration in seconds.
    MAX_NVML_TIME_DELAY = 5
    MAX_OCSP_TIME_DELAY = 10
    MAX_NETWORK_TIME_DELAY = 10
    OCSP_URL = ''
    OCSP_HASH_FUNCTION = sha384
    RIM_SERVICE_BASE_URL = ''
    Certificate_Chain_Verification_Mode = Enum("CERT CHAIN VERIFICATION MODE",
                                               ['SWITCH_ATTESTATION', 'OCSP_RESPONSE',
                                                'VBIOS_RIM_CERT'])
    NVDEC_STATUS = Enum("NVDEC0 status", [("ENABLED", 0xAA), ("DISABLED", 0x55)])
    class Status(Enum):
        VALID = "valid"
        INVALID = "invalid"
        REVOKED = "revoked"
        EXPIRED = "expired"
    INDEX_OF_IK_CERT = 1
    SKU = "PROD"
    claims = {}
    allow_hold_cert = False
    service_key = None
    ROOT_CERT_DIR = os.path.join(parent_dir, "certs")
    RIM_ROOT_CERT = os.path.join(ROOT_CERT_DIR, 'verifier_RIM_root.pem')
    DEVICE_ROOT_CERT = os.path.join(ROOT_CERT_DIR, 'verifier_device_root.pem')
    CLAIMS_VERSION = "2.0"

    @classmethod
    def set_ocsp_url(cls, url):
        if not isinstance(url, str):
            raise ValueError("Incorrect data type for the URL.")  
        if not url:
            raise ValueError("OCSP URL is empty")
        if not url.endswith('/'):
            url += '/'
        cls.OCSP_URL = url

    @classmethod
    def set_rim_service_base_url(cls, url):
        if not isinstance(url, str):
            raise ValueError("Incorrect data type for the URL.")
        if not url:
            raise ValueError("RIM URL is empty")
        if not url.endswith('/'):
            url += '/'
        cls.RIM_SERVICE_BASE_URL = url

    @classmethod
    def set_service_key(cls, service_key):
        if not isinstance(service_key, str):
            raise ValueError("Incorrect data type for the service_key.")
        cls.service_key = service_key

    @classmethod
    def get_sku(cls):
        return cls.SKU

    @classmethod
    def set_sku(cls, sku):
        cls.SKU = sku

    @classmethod
    def reset(cls):
        cls.NONCE = bytes.fromhex("4cff7f5380ead8fad8ec2c531c110aca4302a88f603792801a8ca29ee151af2e")
        cls.current_retry_count = 0
        cls.claims = {}

    @classmethod
    def set_nonce(cls, nonce):
        cls.NONCE = nonce

    def __init__(self):
        self.measurement_comparison = None
        self.parse_attestation_report = None
        self.nonce_comparison = None
        self.attestation_report_bios_version_match = None
        self.rim_bios_version_match = None
        self.rim_bios_measurements_availability = None
        self.bios_rim_schema_validation = None
        self.bios_rim_signature_verification = None
        self.fetch_bios_rim = None
        self.no_driver_vbios_measurement_index_conflict = None
        self.attestation_report_signature_verification = None
        self.switch_attestation_report_cert_chain_validated = None
        self.switch_bios_version = None
        self.switch_arch_is_correct = None
        self.switch_attestation_report_cert_chain_fwid_matched = None
        self.switch_attestation_report_cert_expiration_date = None
        self.switch_attestation_report_cert_status = None
        self.switch_attestation_report_cert_ocsp_status = None
        self.switch_attestation_report_cert_revocation_reason = None
        self.switch_vbios_rim_cert_expiration_date = None
        self.switch_vbios_rim_cert_status = None
        self.switch_vbios_rim_cert_chain_validated = None
        self.switch_vbios_rim_cert_ocsp_status = None
        self.switch_vbios_rim_cert_revocation_reason = None

    @classmethod
    def check_if_attestation_report_available(cls):
        return cls.attestation_report_availability

    @classmethod
    def mark_attestation_report_as_available(cls, flag=True):
        logger.debug("mark_attestation_report_as_available called.")
        cls.attestation_report_availability = flag

    def check_if_switch_attestation_report_cert_chain_fwid_matched(self):
        logger.debug(
            f"check_if_switch_attestation_report_cert_chain_fwid_matched: {self.switch_attestation_report_cert_chain_fwid_matched}")
        return self.switch_attestation_report_cert_chain_fwid_matched

    def mark_switch_attestation_report_cert_chain_fwid_matched(self, flag=True):
        logger.debug("mark_switch_attestation_report_cert_chain_fwid_matched called")
        self.switch_attestation_report_cert_chain_fwid_matched = flag

    def check_switch_attestation_report_cert_expiration_date(self):
        logger.debug(f"check_switch_attestation_report_cert_expiration_date called.{self.switch_attestation_report_cert_expiration_date}")
        return self.switch_attestation_report_cert_expiration_date

    def mark_switch_attestation_report_cert_expiration_date(self, expiration_date):
        logger.debug("mark_switch_attestation_report_cert_expiration_date called.")
        self.switch_attestation_report_cert_expiration_date = expiration_date

    def check_switch_attestation_report_cert_status(self):
        logger.debug(f"check_switch_attestation_report_cert_status called.{self.switch_attestation_report_cert_status}")
        return self.switch_attestation_report_cert_status

    def mark_switch_attestation_report_cert_status(self, cert_status):
        logger.debug("mark_switch_attestation_report_cert_status called.")
        self.switch_attestation_report_cert_status = cert_status

    def check_if_switch_attestation_report_cert_chain_validated(self):
        return self.switch_attestation_report_cert_chain_validated

    def mark_switch_attestation_report_cert_chain_validated(self, flag=True):
        logger.debug("mark_switch_attestation_report_cert_chain_validated called")
        self.switch_attestation_report_cert_chain_validated = flag

    def check_switch_attestation_report_cert_ocsp_status(self):
        logger.debug(f"check_switch_attestation_report_cert_ocsp_status: {self.switch_attestation_report_cert_ocsp_status}")
        return self.switch_attestation_report_cert_ocsp_status

    def mark_switch_attestation_report_cert_ocsp_status(self, ocsp_status):
        logger.debug("mark_switch_attestation_report_cert_ocsp_status called.")
        self.switch_attestation_report_cert_ocsp_status = ocsp_status

    def check_switch_attestation_report_cert_revocation_reason(self):
        logger.debug(f"check_switch_attestation_report_cert_revocation_reason called.{self.switch_attestation_report_cert_revocation_reason}")
        return self.switch_attestation_report_cert_revocation_reason

    def mark_switch_attestation_report_cert_revocation_reason(self, revocation_reason):
        logger.debug("mark_switch_attestation_report_cert_revocation_reason called.")
        self.switch_attestation_report_cert_revocation_reason = revocation_reason

    def check_if_attestation_report_signature_verified(self):
        return self.attestation_report_signature_verification

    def mark_attestation_report_signature_verified(self, flag=True):
        logger.debug("mark_attestation_report_signature_verified called")
        self.attestation_report_signature_verification = flag

    def check_if_bios_rim_fetched(self):
        return self.fetch_bios_rim

    def mark_vbios_rim_fetched(self, flag=True):
        logger.debug("mark_vbios_rim_fetched called.")
        self.fetch_bios_rim = flag

    def check_if_bios_rim_signature_verified(self):
        return self.bios_rim_signature_verification

    def check_if_switch_arch_is_correct(self):
        return self.switch_arch_is_correct

    def mark_vbios_rim_signature_verified(self, flag=True):
        logger.debug("mark_vbios_rim_signature_verified called.")
        self.bios_rim_signature_verification = flag

    def check_if_bios_rim_schema_validated(self):
        return self.bios_rim_schema_validation

    def mark_bios_rim_schema_validated(self, flag=True):
        logger.debug("mark_bios_rim_schema_validated called.")
        self.bios_rim_schema_validation = flag

    def check_switch_vbios_rim_cert_expiration_date(self):
        logger.debug(f"check_switch_vbios_rim_cert_expiration_date called.{self.switch_vbios_rim_cert_expiration_date}")
        return self.switch_vbios_rim_cert_expiration_date

    def mark_switch_vbios_rim_cert_expiration_date(self, expiration_date):
        logger.debug("mark_switch_vbios_rim_cert_expiration_date called.")
        self.switch_vbios_rim_cert_expiration_date = expiration_date

    def check_switch_vbios_rim_cert_status(self):
        logger.debug(f"check_switch_vbios_rim_cert_status called.{self.switch_vbios_rim_cert_status}")
        return self.switch_vbios_rim_cert_status

    def mark_switch_vbios_rim_cert_status(self, cert_status):
        logger.debug("mark_switch_vbios_rim_cert_status called.")
        self.switch_vbios_rim_cert_status = cert_status

    def check_if_switch_vbios_rim_cert_chain_validated(self):
        logger.debug(f"check_if_switch_vbios_rim_cert_chain_validated: {self.switch_vbios_rim_cert_chain_validated}")
        return self.switch_vbios_rim_cert_chain_validated

    def mark_switch_vbios_rim_cert_chain_validated(self, flag=True):
        logger.debug("mark_switch_vbios_rim_cert_chain_validated called")
        self.switch_vbios_rim_cert_chain_validated = flag

    def check_switch_vbios_rim_cert_ocsp_status(self):
        logger.debug(f"check_switch_vbios_rim_cert_ocsp_status: {self.switch_vbios_rim_cert_ocsp_status}")
        return self.switch_vbios_rim_cert_ocsp_status

    def mark_switch_vbios_rim_cert_ocsp_status(self, ocsp_status):
        logger.debug("mark_switch_vbios_rim_cert_ocsp_status called.")
        self.switch_vbios_rim_cert_ocsp_status = ocsp_status

    def check_switch_vbios_rim_cert_revocation_reason(self):
        logger.debug(f"check_switch_vbios_rim_cert_revocation_reason called.{self.switch_vbios_rim_cert_revocation_reason}")
        return self.switch_vbios_rim_cert_revocation_reason

    def mark_switch_vbios_rim_cert_revocation_reason(self, revocation_reason):
        logger.debug("mark_switch_vbios_rim_cert_revocation_reason called.")
        self.switch_vbios_rim_cert_revocation_reason = revocation_reason

    def check_rim_bios_measurements_availability(self):
        return self.rim_bios_measurements_availability

    def mark_rim_vbios_measurements_as_available(self, flag=True):
        logger.debug("mark_rim_vbios_measurements_as_available called.")
        self.rim_bios_measurements_availability = flag

    def check_if_measurements_are_matching(self):
        if self.measurement_comparison is True:
            return "success"
        elif self.measurement_comparison is False:
            return "fail"
        else:
            return None

    def mark_measurements_as_matching(self, flag=True):
        logger.debug("mark_measurements_as_matching called.")
        self.measurement_comparison = flag

    def check_if_rim_bios_version_matches(self):
        return self.rim_bios_version_match

    def mark_rim_vbios_version_as_matching(self, flag=True):
        logger.debug("mark_rim_vbios_version_as_matching called.")
        self.rim_bios_version_match = flag

    def check_if_nonce_are_matching(self):
        return self.nonce_comparison

    def mark_nonce_as_matching(self, flag=True):
        logger.debug("mark_nonce_as_matching called.")
        self.nonce_comparison = flag

    def check_if_attestation_report_parsed_successfully(self):
        return self.parse_attestation_report

    def mark_attestation_report_parsed(self, flag=True):
        logger.debug("mark_attestation_report_parsed called.")
        self.parse_attestation_report = flag

    def mark_switch_arch_is_correct(self, flag=True):
        logger.debug("mark_switch_arch_is_correct called.")
        self.switch_arch_is_correct = flag

    def mark_bios_version(self, bios_version):
        logger.debug("mark_bios_version called.")
        self.switch_bios_version = bios_version

    def check_bios_version(self):
        return self.switch_bios_version

    def check_if_attestation_report_bios_version_matches(self):
        return self.attestation_report_bios_version_match

    def mark_attestation_report_vbios_version_as_matching(self, flag=True):
        logger.debug("mark_attestation_report_vbios_version_as_matching called.")
        self.attestation_report_bios_version_match = flag

    def check_if_no_driver_bios_measurement_index_conflict(self):
        return self.no_driver_vbios_measurement_index_conflict

    def mark_no_driver_vbios_measurement_index_conflict(self, flag=True):
        logger.debug("mark_no_driver_vbios_measurement_conflict called.")
        self.no_driver_vbios_measurement_index_conflict = flag

    def check_status(self):
        if self.check_if_switch_attestation_report_cert_chain_validated() and \
                self.check_if_switch_arch_is_correct() and \
                self.check_if_attestation_report_parsed_successfully() and \
                ((self.check_switch_attestation_report_cert_status() == 'valid') or
                 (BaseSettings.allow_hold_cert and self.check_switch_attestation_report_cert_status() == 'revoked' and self.check_switch_attestation_report_cert_revocation_reason() == 'certificate_hold')) and \
                ((self.check_switch_attestation_report_cert_ocsp_status() == 'good') or
                 (BaseSettings.allow_hold_cert and self.check_switch_attestation_report_cert_ocsp_status() == 'revoked' and self.check_switch_attestation_report_cert_revocation_reason() == 'certificate_hold')) and \
                self.check_if_switch_attestation_report_cert_chain_fwid_matched() and \
                self.check_if_nonce_are_matching() and \
                self.check_if_attestation_report_signature_verified() and \
                self.check_if_bios_rim_fetched() and \
                self.check_if_bios_rim_schema_validated() and \
                self.check_if_switch_vbios_rim_cert_chain_validated() and \
                self.check_if_bios_rim_signature_verified() and \
                ((self.check_switch_vbios_rim_cert_status() == 'valid') or
                 (BaseSettings.allow_hold_cert and self.check_switch_vbios_rim_cert_status() == 'revoked' and self.check_switch_vbios_rim_cert_revocation_reason() == 'certificate_hold')) and \
                ((self.check_switch_vbios_rim_cert_ocsp_status() == 'good') or
                 (BaseSettings.allow_hold_cert and self.check_switch_vbios_rim_cert_ocsp_status() == 'revoked' and self.check_switch_vbios_rim_cert_revocation_reason() == 'certificate_hold')) and \
                self.check_if_rim_bios_version_matches() and \
                self.check_rim_bios_measurements_availability() and \
                self.check_if_measurements_are_matching() == "success":
            BaseSettings.test_result = True
            return True
        else:
            BaseSettings.test_result = False
            return False


class LS10Settings(BaseSettings):
    signature_length = 96
    HashFunction = sha384
    MAX_CERT_CHAIN_LENGTH = 5
    HashFunctionNamespace = "{http://www.w3.org/2001/04/xmlenc#sha384}"
    SwitchArch = 2 # 2 is for LS10
    RIM_DIRECTORY_PATH = os.path.join(parent_dir, "samples")
    VBIOS_RIM_PATH = ""
    ATTESTATION_REPORT_PATH = os.path.join(RIM_DIRECTORY_PATH, "attestationReport.txt")
    SWITCH_ATTESTATION_CERTIFICATES_PATH = os.path.join(RIM_DIRECTORY_PATH, "gpuAkCertChain.txt")
    ocsp_nonce_disabled = False

    @classmethod
    def set_vbios_rim_path(cls, path):
        cls.VBIOS_RIM_PATH = path

    @classmethod
    def set_attestation_report_path(cls, path):
        cls.ATTESTATION_REPORT_PATH = path

    @classmethod
    def set_switch_attestation_certificates_path(cls, path):
        cls.SWITCH_ATTESTATION_CERTIFICATES_PATH = path

    @classmethod
    def set_ocsp_nonce_disabled(cls, ocsp_nonce_disabled):
        cls.ocsp_nonce_disabled = ocsp_nonce_disabled
