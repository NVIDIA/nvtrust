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
import logging
import sys
from verifier.__about__ import __author__, __copyright__, __version__

info_log = logging.getLogger('gpu-verifier-info')
info_log.setLevel(logging.INFO)
shandler = logging.StreamHandler(sys.stdout)
info_log.addHandler(shandler)

parent_dir = os.path.dirname(os.path.abspath(__file__))
logger_file_path = os.path.join(os.getcwd(), "verifier.log")

if os.path.exists(logger_file_path):
    os.remove(logger_file_path)

event_log = logging.getLogger('gpu-verifier-event')
event_log.setLevel(logging.DEBUG)
fhandler = logging.FileHandler(logger_file_path)
fhandler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s: %(message)s", '%m-%d-%Y %H:%M:%S'))
event_log.addHandler(fhandler)

event_log.debug("----------STARTING----------")


class BaseSettings:
    SIZE_OF_NONCE_IN_BYTES = 32
    SIZE_OF_NONCE_IN_HEX_STR = 64
    gpu_availability = False
    attestation_report_availability = False
    TEST_NO_GPU_NUMBER_OF_GPUS = 1
    NONCE = "4cff7f5380ead8fad8ec2c531c110aca4302a88f603792801a8ca29ee151af2e"
    # The maximum number of times the CC ADMIN will retry the GPU attestation.
    MAX_RETRY_COUNT = 3
    current_retry_count = 0
    # The Timeout duration in seconds.
    MAX_NVML_TIME_DELAY = 5
    MAX_OCSP_TIME_DELAY = 10
    MAX_NETWORK_TIME_DELAY = 10
    OCSP_URL = os.getenv('NV_OCSP_URL', 'https://ocsp.ndis.nvidia.com/')
    OCSP_HASH_FUNCTION = sha384
    RIM_SERVICE_BASE_URL = os.getenv('NV_RIM_URL', 'https://rim.attestation.nvidia.com/v1/rim/')
    Certificate_Chain_Verification_Mode = Enum("CERT CHAIN VERIFICATION MODE",
                                               ['GPU_ATTESTATION', 'OCSP_RESPONSE', 'DRIVER_RIM_CERT',
                                                'VBIOS_RIM_CERT'])
    NVDEC_STATUS = Enum("NVDEC0 status", [("ENABLED", 0xAA), ("DISABLED", 0x55)])
    INDEX_OF_IK_CERT = 1
    SKU = "PROD"
    claims = {}
    allow_hold_cert = False
    ROOT_CERT_DIR = os.path.join(parent_dir, "certs")
    RIM_ROOT_CERT = os.path.join(ROOT_CERT_DIR, 'verifier_RIM_root.pem')
    DEVICE_ROOT_CERT = os.path.join(ROOT_CERT_DIR, 'verifier_device_root.pem')

    EXECUTION_SEQUENCE_INDEX = {
        'GPU_AVAILABILITY': 0,
        'ATTESTATION_REPORT_AVAILABILITY': 1,
        'GPU_INFO_FETCH': 2,
        'CORRECT_GPU_ARCH': 3,
        'ROOT_CERT_AVAILABILITY': 4,
        'GPU_CERT_CHAIN_VERIFIED': 5,
        'GPU_CERT_OCSP_CERT_CHAIN_VERIFICATION': 6,
        'GPU_CERT_OCSP_SIGNATURE_VERIFICATION': 7,
        'GPU_CERT_OCSP_NONCE_MATCH': 8,
        'GPU_CERT_CHECK_COMPLETE': 9,
        'ATTESTATION_REPORT_MSR_AVAILABILITY': 10,
        'ATTESTATION_REPORT_PARSED': 11,
        'NONCE_MATCH': 12,
        'ATTESTATION_REPORT_DRV_VERSION_MATCH': 13,
        'ATTESTATION_REPORT_VBIOS_VERSION_MATCH': 14,
        'ATTESTATION_REPORT_VERIFICATION': 15,
        'DRIVER_RIM_FETCH': 16,
        'DRIVER_RIM_MEASUREMENT_AVAILABILITY': 17,
        'DRIVER_RIM_SCHEMA_VALIDATION': 18,
        'DRIVER_RIM_VERSION_MATCH': 19,
        'DRIVER_RIM_CERT_EXTRACT': 20,
        'DRIVER_RIM_SIGNATURE_VERIFICATION': 21,
        'VBIOS_RIM_FETCH': 22,
        'VBIOS_RIM_MEASUREMENT_AVAILABILITY': 23,
        'VBIOS_RIM_SCHEMA_VALIDATION': 24,
        'VBIOS_RIM_VERSION_MATCH': 25,
        'VBIOS_RIM_CERT_EXTRACT': 26,
        'VBIOS_RIM_SIGNATURE_VERIFICATION': 27,
        'DRV_VBIOS_MSR_INDEX_CONFLICT': 28,
        'MEASUREMENT_MATCH': 29,
    }

    @classmethod
    def set_ocsp_url(cls, url):
        if not isinstance(url, str):
            raise ValueError("Incorrect data type for the URL.")
        cls.OCSP_URL = url

    @classmethod
    def set_rim_service_base_url(cls, url):
        if not isinstance(url, str):
            raise ValueError("Incorrect data type for the URL.")
        cls.RIM_SERVICE_BASE_URL = url

    @classmethod
    def get_sku(cls):
        return cls.SKU

    @classmethod
    def set_sku(cls, sku):
        cls.SKU = sku

    @classmethod
    def is_retry_allowed(cls):
        if (cls.current_retry_count < cls.MAX_RETRY_COUNT):
            cls.current_retry_count += 1
            return True
        else:
            return False

    @classmethod
    def reset(cls):
        cls.NONCE = bytes.fromhex("4cff7f5380ead8fad8ec2c531c110aca4302a88f603792801a8ca29ee151af2e")
        cls.current_retry_count = 0
        cls.claims = {}

    @classmethod
    def set_nonce(cls, nonce):
        cls.NONCE = nonce

    def __init__(self):
        self.measurement_comparison = False
        self.gpu_arch_is_correct = False
        self.attestation_report_measurements_availability = False
        self.gpu_info_fetch = False
        self.gpu_cert_chain_verification = False
        self.root_cert_availability = False
        self.attestation_report_verification = False
        self.parse_attestation_report = False
        self.nonce_comparison = False
        self.attestation_report_driver_version_match = False
        self.attestation_report_vbios_version_match = False
        self.rim_driver_version_match = False
        self.rim_vbios_version_match = False
        self.rim_driver_measurements_availability = False
        self.rim_vbios_measurements_availability = False
        self.driver_rim_schema_validation = False
        self.vbios_rim_schema_validation = False
        self.driver_rim_signature_verification = False
        self.vbios_rim_signature_verification = False
        self.driver_rim_certificate_extraction = False
        self.vbios_rim_certificate_extraction = False
        self.fetch_driver_rim = False
        self.fetch_vbios_rim = False
        self.no_driver_vbios_measurement_index_conflict = False
        self.gpu_certificate_ocsp_nonce_match = False
        self.gpu_certificate_ocsp_signature_verification = False
        self.gpu_certificate_ocsp_cert_chain_verification = False
        self.gpu_cert_check_complete = False
        self.gpu_attestation_report_cert_chain_validated = False
        self.driver_rim_certificate_validated = False
        self.vbios_rim_certificate_validated = False
        self.attestation_report_signature_verification = False
        self.gpu_driver_version = ""
        self.gpu_vbios_version = ""

    @classmethod
    def mark_attestation_report_as_available(cls):
        event_log.debug("mark_attestation_report_as_available called.")
        cls.attestation_report_availability = True

    def check_if_gpu_attestation_report_cert_chain_validated(self):
        event_log.debug(
            f"check_if_gpu_attestation_report_cert_chain_validated: {self.gpu_attestation_report_cert_chain_validated}")
        return self.gpu_attestation_report_cert_chain_validated

    def mark_gpu_attestation_report_cert_chain_validated(self):
        event_log.debug("mark_gpu_attestation_report_cert_chain_validated called")
        self.gpu_attestation_report_cert_chain_validated = True

    def check_if_attestation_report_signature_verified(self):
        event_log.debug(f"check_if_attestation_report_signature_verified: {self.attestation_report_signature_verification}")
        return self.attestation_report_signature_verification

    def mark_attestation_report_signature_verified(self):
        event_log.debug("mark_attestation_report_signature_verified called")
        self.attestation_report_signature_verification = True

    def check_if_driver_rim_fetched(self):
        event_log.debug(f"check_if_driver_rim_fetched: {self.fetch_driver_rim}")
        return self.fetch_driver_rim

    def mark_driver_rim_fetched(self):
        event_log.debug("mark_driver_rim_fetched called")
        self.fetch_driver_rim = True

    def check_if_vbios_rim_fetched(self):
        event_log.debug(f"check_if_vbios_rim_fetched: {self.fetch_vbios_rim}")
        return self.fetch_vbios_rim

    def mark_vbios_rim_fetched(self):
        event_log.debug("mark_vbios_rim_fetched called.")
        self.fetch_vbios_rim = True

    def check_if_driver_rim_signature_verified(self):
        event_log.debug(f"check_if_driver_rim_signature_verified: {self.driver_rim_signature_verification}")
        return self.driver_rim_signature_verification

    def mark_driver_rim_signature_verified(self):
        event_log.debug("mark_driver_rim_signature_verified called.")
        self.driver_rim_signature_verification = True

    def check_if_vbios_rim_signature_verified(self):
        event_log.debug(f"check_if_vbios_rim_signature_verified: {self.vbios_rim_signature_verification}")
        return self.vbios_rim_signature_verification

    def mark_vbios_rim_signature_verified(self):
        event_log.debug("mark_vbios_rim_signature_verified called.")
        self.vbios_rim_signature_verification = True

    def check_if_driver_rim_schema_validated(self):
        event_log.debug(f"check_if_driver_rim_schema_validated: {self.driver_rim_schema_validation}")
        return self.driver_rim_schema_validation

    def mark_driver_rim_schema_validated(self):
        event_log.debug("mark_driver_rim_schema_validated called.")
        self.driver_rim_schema_validation = True

    def check_gpu_driver_version(self):
        event_log.debug(f"check_gpu_driver_version called.{self.gpu_driver_version}")
        return self.gpu_driver_version

    def mark_gpu_driver_version(self, driver_version):
        event_log.debug("mark_gpu_driver_version called.")
        self.gpu_driver_version = driver_version

    def check_gpu_vbios_version(self):
        event_log.debug(f"check_gpu_vbios_version called.{self.gpu_vbios_version}")
        return self.gpu_vbios_version

    def mark_gpu_vbios_version(self, vbios_version):
        event_log.debug("mark_gpu_vbios_version called.")
        if vbios_version is not None:
            self.gpu_vbios_version = vbios_version.upper()

    def check_if_vbios_rim_schema_validated(self):
        event_log.debug(f"check_if_vbios_rim_schema_validated: {self.vbios_rim_schema_validation}")
        return self.vbios_rim_schema_validation

    def mark_vbios_rim_schema_validated(self):
        event_log.debug("mark_vbios_rim_schema_validated called.")
        self.vbios_rim_schema_validation = True

    def check_rim_driver_measurements_availability(self):
        event_log.debug(f"check_rim_driver_measurements_availability: {self.rim_driver_measurements_availability}")
        return self.rim_driver_measurements_availability

    def mark_rim_driver_measurements_as_available(self):
        event_log.debug("mark_rim_driver_measurements_as_available called.")
        self.rim_driver_measurements_availability = True

    def check_rim_vbios_measurements_availability(self):
        event_log.debug(f"check_rim_vbios_measurements_availability: {self.rim_vbios_measurements_availability}")
        return self.rim_vbios_measurements_availability

    def mark_rim_vbios_measurements_as_available(self):
        event_log.debug("mark_rim_vbios_measurements_as_available called.")
        self.rim_vbios_measurements_availability = True


    def check_if_measurements_are_matching(self):
        if self.measurement_comparison:
            return "success"
        else:
            return "fail"

    def mark_measurements_as_matching(self):
        event_log.debug("mark_measurements_as_matching called.")
        self.measurement_comparison = True


    def check_if_rim_driver_version_matches(self):
        event_log.debug(f"check_if_rim_driver_version_matches: {self.rim_driver_version_match}")
        return self.rim_driver_version_match

    def mark_rim_driver_version_as_matching(self):
        event_log.debug("mark_rim_driver_version_as_matching called.")
        self.rim_driver_version_match = True

    def check_if_rim_vbios_version_matches(self):
        event_log.debug(f"check_if_rim_vbios_version_matches: {self.rim_vbios_version_match}")
        return self.rim_vbios_version_match

    def mark_rim_vbios_version_as_matching(self):
        event_log.debug("mark_rim_vbios_version_as_matching called.")
        self.rim_vbios_version_match = True

    def check_if_driver_rim_cert_validated(self):
        event_log.debug(f"check_if_driver_rim_cert_validated: {self.driver_rim_certificate_validated}")
        return self.driver_rim_certificate_validated

    def mark_driver_rim_cert_validated_successfully(self):
        event_log.debug("mark_driver_rim_cert_validatedd_successfully called.")
        self.driver_rim_certificate_validated = True

    def check_if_vbios_rim_cert_extracted(self):
        event_log.debug(f"check_if_vbios_rim_cert_extracted: {self.vbios_rim_certificate_extraction}")
        return self.vbios_rim_certificate_extraction

    def mark_vbios_rim_cert_extracted_successfully(self):
        event_log.debug("mark_vbios_rim_cert_extracted_successfully called.")
        self.vbios_rim_certificate_extraction = True

    def check_if_vbios_rim_cert_validated(self):
        event_log.debug(f"check_if_vbios_rim_cert_extracted: {self.vbios_rim_certificate_validated}")
        return self.vbios_rim_certificate_validated

    def mark_vbios_rim_cert_validated_successfully(self):
        event_log.debug("mark_vbios_rim_cert_validated_successfully called.")
        self.vbios_rim_certificate_validated = True

    def check_if_gpu_arch_is_correct(self):
        event_log.debug(f"check_if_gpu_arch_is_correct: {self.gpu_arch_is_correct}")
        return self.gpu_arch_is_correct

    def mark_gpu_arch_is_correct(self):
        event_log.debug("mark_gpu_arch_is_correct called.")
        self.gpu_arch_is_correct = True

    def check_if_nonce_are_matching(self):
        event_log.debug(f"check_if_nonce_are_matching: {self.nonce_comparison}")
        return self.nonce_comparison

    def mark_nonce_as_matching(self):
        event_log.debug("mark_nonce_as_matching called.")
        self.nonce_comparison = True

    def check_if_attestation_report_parsed_successfully(self):
        event_log.debug(f"check_if_attestation_report_parsed_successfully: {self.parse_attestation_report}")
        return self.parse_attestation_report

    def mark_attestation_report_parsed(self):
        event_log.debug("mark_attestation_report_parsed called.")
        self.parse_attestation_report = True

    def check_if_attestation_report_driver_version_matches(self):
        event_log.debug(
            f"check_if_attestation_report_driver_version_matches: {self.attestation_report_driver_version_match}")
        return self.attestation_report_driver_version_match

    def mark_attestation_report_driver_version_as_matching(self):
        event_log.debug("mark_attestation_report_driver_version_as_matching called.")
        self.attestation_report_driver_version_match = True

    def check_if_attestation_report_vbios_version_matches(self):
        event_log.debug(
            f"check_if_attestation_report_vbios_version_matches: {self.attestation_report_vbios_version_match}")
        return self.attestation_report_vbios_version_match

    def mark_attestation_report_vbios_version_as_matching(self):
        event_log.debug("mark_attestation_report_vbios_version_as_matching called.")
        self.attestation_report_vbios_version_match = True

    def check_if_no_driver_vbios_measurement_index_conflict(self):
        event_log.debug(
            f"check_if_no_driver_vbios_measurement_index_conflict: {self.no_driver_vbios_measurement_index_conflict}")
        return self.no_driver_vbios_measurement_index_conflict

    def mark_no_driver_vbios_measurement_index_conflict(self):
        event_log.debug("mark_no_driver_vbios_measurement_conflict called.")
        self.no_driver_vbios_measurement_index_conflict = True

    def check_status(self):
        if self.check_if_gpu_arch_is_correct() and \
                self.check_if_gpu_attestation_report_cert_chain_validated() and \
                self.check_if_attestation_report_parsed_successfully() and \
                self.check_if_nonce_are_matching() and \
                self.check_if_attestation_report_driver_version_matches() and \
                self.check_if_attestation_report_vbios_version_matches() and \
                self.check_if_attestation_report_signature_verified() and \
                self.check_if_driver_rim_fetched() and \
                self.check_if_driver_rim_schema_validated() and \
                self.check_if_driver_rim_cert_validated() and \
                self.check_if_driver_rim_signature_verified() and \
                self.check_rim_driver_measurements_availability() and \
                self.check_if_vbios_rim_fetched() and \
                self.check_if_vbios_rim_schema_validated() and \
                self.check_if_vbios_rim_signature_verified() and \
                self.check_rim_vbios_measurements_availability() and \
                self.check_if_no_driver_vbios_measurement_index_conflict() and \
                self.check_if_measurements_are_matching() == "success":
            BaseSettings.test_result = True
            return True
        else:
            BaseSettings.test_result = False
            return False


class HopperSettings(BaseSettings):
    signature_length = 96
    HashFunction = sha384
    MAX_CERT_CHAIN_LENGTH = 5
    HashFunctionNamespace = "{http://www.w3.org/2001/04/xmlenc#sha384}"
    GpuArch = "HOPPER"
    RIM_DIRECTORY_PATH = os.path.join(parent_dir, "samples")
    TEST_NO_GPU_DRIVER_RIM_PATH = os.path.join(RIM_DIRECTORY_PATH, "Driver_RIM_test_no_gpu.swidtag")
    DRIVER_RIM_PATH = ""
    TEST_NO_GPU_VBIOS_RIM_PATH = os.path.join(RIM_DIRECTORY_PATH, "1010_0200_882_96005E0001_test_no_gpu.swidtag")
    VBIOS_RIM_PATH = ""
    ATTESTATION_REPORT_PATH = os.path.join(RIM_DIRECTORY_PATH, "attestationReport.txt")
    GPU_ATTESTATION_CERTIFICATES_PATH = os.path.join(RIM_DIRECTORY_PATH, "gpuAkCertChain.txt")

    @classmethod
    def set_driver_rim_path(cls, path):
        cls.DRIVER_RIM_PATH = path

    @classmethod
    def set_vbios_rim_path(cls, path):
        cls.VBIOS_RIM_PATH = path

    @classmethod
    def set_attestation_report_path(cls, path):
        cls.ATTESTATION_REPORT_PATH = path

    @classmethod
    def set_gpu_attestation_certificates_path(cls, path):
        cls.GPU_ATTESTATION_CERTIFICATES_PATH = path
