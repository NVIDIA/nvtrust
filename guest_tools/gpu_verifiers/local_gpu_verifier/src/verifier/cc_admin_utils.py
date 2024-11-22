#
# SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

import os
import secrets
import string
import sys
from urllib import request
from urllib.error import HTTPError
import json
import base64


from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ocsp, OCSPNonce
from cryptography import x509

from verifier.attestation import AttestationReport
from verifier.config import (
    BaseSettings,
    info_log,
    event_log,
)
from verifier.utils import (
    format_vbios_version,
    function_wrapper_with_timeout,
)
from verifier.exceptions import (
    NoCertificateError,
    IncorrectNumberOfCertificatesError,
    NonceMismatchError,
    DriverVersionMismatchError,
    SignatureVerificationError,
    VBIOSVersionMismatchError,
    RIMFetchError,
    InvalidNonceError
)

class CcAdminUtils:
    """ A class to provide the required functionalities for the CC ADMIN to perform the GPU attestation.
    """

    @staticmethod
    def extract_fwid(cert):
        """ A static function to extract the FWID data from the given certificate.

        Args:
            cert (OpenSSL.crypto.X509): The certificate whose FWID data is needed to be fetched.

        Returns:
            [str]: the FWID as a hex string extracted from the certificate if
                   it is present otherwise returns an empty string.
        """
        result = ''
        # The OID for the FWID extension.
        TCG_DICE_FWID_OID = '2.23.133.5.4.1'
        cryptography_cert = cert.to_cryptography()

        for i in range(len(cryptography_cert.extensions)):
            oid_obj = (vars(cryptography_cert.extensions)['_extensions'][i]).oid
            if getattr(oid_obj, 'dotted_string') == TCG_DICE_FWID_OID:
                # The FWID data is the last 48 bytes.
                result = vars((vars(cryptography_cert.extensions)['_extensions'][i]).value)['_value'][-48:].hex()

        return result

    @staticmethod
    def verify_gpu_certificate_chain(cert_chain, settings, attestation_report_fwid):
        """ A static function to perform the GPU device certificate chain verification.

        Args:
            cert_chain (list): A list containing the certificate objects of the device certificate chain.
            settings (config.HopperSettings): the object containing the various config info.
            attestation_report_fwid (str): the hexadecimal string of the FWID in the attestation report.

        Returns:
            [bool]: True if the verification is successful, otherwise False.
        """
        # Skipping the comparision of FWID in the attestation certificate if the Attestation report does not contains the FWID.
        if attestation_report_fwid != '':

            if attestation_report_fwid != CcAdminUtils.extract_fwid(cert_chain[0]):
                info_log.error("\t\tThe firmware ID in the device certificate chain is not matching with the one in the attestation report.")
                event_log.info(f"\t\tThe FWID read from the attestation report is : {attestation_report_fwid}")
                return False

            info_log.info("\t\tThe firmware ID in the device certificate chain is matching with the one in the attestation report.")

        return CcAdminUtils.verify_certificate_chain(cert_chain, settings, BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION)

    @staticmethod
    def verify_certificate_chain(cert_chain, settings, mode):
        """ Performs the certificate chain verification.

        Args:
            cert_chain (list): the certificate chain as a list with the root
                               cert at the end of the list.
            settings (config.HopperSettings): the object containing the various config info.
            mode (<enum 'CERT CHAIN VERIFICATION MODE'>): Used to determine if the certificate chain
                            verification is for the GPU attestation certificate chain or RIM certificate chain
                            or the ocsp response certificate chain.

        Raises:
            NoCertificateError: it is raised if the cert_chain list is empty.
            IncorrectNumberOfCertificatesError: it is raised if the number of
                                certificates in cert_chain list is unexpected.

        Returns:
            [bool]: True if the verification is successful, otherwise False.
        """
        assert isinstance(cert_chain, list)

        number_of_certificates = len(cert_chain)

        event_log.debug(f"verify_certificate_chain() called for {str(mode)}")
        event_log.debug(f'Number of certificates : {number_of_certificates}')

        if number_of_certificates < 1:
            event_log.error("\t\tNo certificates found in certificate chain.")
            raise NoCertificateError("\t\tNo certificates found in certificate chain.")

        if number_of_certificates != settings.MAX_CERT_CHAIN_LENGTH and mode == BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION:
            event_log.error("\t\tThe number of certificates fetched from the GPU is unexpected.")
            raise IncorrectNumberOfCertificatesError("\t\tThe number of certificates fetched from the GPU is unexpected.")

        store = crypto.X509Store()
        index = number_of_certificates - 1
        while index > -1:
            if index == number_of_certificates - 1:
                # The root CA certificate is stored at the end in the cert chain.
                store.add_cert(cert_chain[index])
                index = index - 1
            else:
                store_context = crypto.X509StoreContext(store, cert_chain[index])
                try:
                    store_context.verify_certificate()
                    store.add_cert(cert_chain[index])
                    index = index - 1
                except crypto.X509StoreContextError as e:
                    event_log.info(f'Cert chain verification is failing at index : {index}')
                    event_log.error(e)
                    return False
        return True

    @staticmethod
    def convert_cert_from_cryptography_to_pyopenssl(cert):
        """ A static method to convert the "Cryptography" X509 certificate object to "pyOpenSSL"
        X509 certificate object.

        Args:
            cert (cryptography.hazmat.backends.openssl.x509._Certificate): the input certificate object.

        Returns:
            [OpenSSL.crypto.X509]: the converted X509 certificate object.
        """
        return crypto.load_certificate(type=crypto.FILETYPE_ASN1, buffer = cert.public_bytes(serialization.Encoding.DER))

    @staticmethod
    def ocsp_certificate_chain_validation(cert_chain, settings, mode):
        """ A static method to perform the ocsp status check of the input certificate chain along with the
        signature verification and the cert chain verification if the ocsp response message received.

        Args:
            cert_chain (list): the list of the input certificates of the certificate chain.
            settings (config.HopperSettings): the object containing the various config info.
            mode (<enum 'CERT CHAIN VERIFICATION MODE'>): Used to determine if the certificate chain
                            verification is for the GPU attestation certificate chain or RIM certificate chain
                            or the ocsp response certificate chain.

        Returns:
            [Bool]: True if the ocsp status of all the appropriate certificates in the
                    certificate chain, otherwise False.
        """
        assert isinstance(cert_chain, list)
        revoked_status = False
        start_index = 0
        gpu_attestation_warning = ""

        if mode == BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION:
            start_index = 1

        end_index = len(cert_chain) - 1

        for i, cert in enumerate(cert_chain):
            cert_chain[i] = cert.to_cryptography()

        for i in range(start_index, end_index):
            request_builder = ocsp.OCSPRequestBuilder()
            request_builder = request_builder.add_certificate(cert_chain[i], cert_chain[i + 1], SHA384())
            nonce  = CcAdminUtils.generate_nonce(BaseSettings.SIZE_OF_NONCE_IN_BYTES)
            request_builder = request_builder.add_extension(extval = OCSPNonce(nonce),
                                                            critical = True)
            request = request_builder.build()
            # Making the network call in a separate thread.
            ocsp_response = function_wrapper_with_timeout([CcAdminUtils.send_ocsp_request,
                                                           request.public_bytes(serialization.Encoding.DER),
                                                           "send_ocsp_request"],
                                                           BaseSettings.MAX_OCSP_TIME_DELAY)

            # Verifying the ocsp response certificate chain.
            ocsp_response_leaf_cert = crypto.load_certificate(type=crypto.FILETYPE_ASN1,
                                                              buffer = ocsp_response.certificates[0].public_bytes(serialization.Encoding.DER))

            ocsp_cert_chain = [ocsp_response_leaf_cert]

            for j in range(i, len(cert_chain)):
                ocsp_cert_chain.append(CcAdminUtils.convert_cert_from_cryptography_to_pyopenssl(cert_chain[j]))

            ocsp_cert_chain_verification_status = CcAdminUtils.verify_certificate_chain(ocsp_cert_chain,
                                                                                        settings,
                                                                                        BaseSettings.Certificate_Chain_Verification_Mode.OCSP_RESPONSE)

            if not ocsp_cert_chain_verification_status:
                info_log.error(f"\t\tThe ocsp response certificate chain verification failed for {cert_chain[i].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}.")
                return False, gpu_attestation_warning
            elif i == end_index - 1:
                info_log.debug("\t\tGPU Certificate OCSP Cert chain is verified")


            # Verifying the signature of the ocsp response message.
            if not CcAdminUtils.verify_ocsp_signature(ocsp_response):
                info_log.error(f"\t\tThe ocsp response response for certificate {cert_chain[i].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value} failed due to signature verification failure.")
                return False, gpu_attestation_warning
            elif i == end_index - 1:
                info_log.debug("\t\tGPU Certificate OCSP Signature is verified")

            if nonce != ocsp_response.extensions.get_extension_for_class(OCSPNonce).value.nonce:
                info_log.error("\t\tThe nonce in the OCSP response message is not matching with the one passed in the OCSP request message.")
                return False, gpu_attestation_warning
            elif i == end_index - 1:
                info_log.debug("\t\tGPU Certificate OCSP Nonce is matching")

            if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                info_log.error("\t\tCouldn't receive a proper response from the OCSP server.")
                return False, gpu_attestation_warning

            #OCSP response can have 3 status - Good, Revoked (with a reason) or Unknown
            if ocsp_response.certificate_status != ocsp.OCSPCertStatus.GOOD:
                if x509.ReasonFlags.certificate_hold == ocsp_response.revocation_reason and \
                BaseSettings.allow_hold_cert and \
                (mode == BaseSettings.Certificate_Chain_Verification_Mode.DRIVER_RIM_CERT or BaseSettings.Certificate_Chain_Verification_Mode.VBIOS_RIM_CERT):
                    warning = f"THE CERTIFICATE {cert_chain[i].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value} IS REVOKED WITH THE STATUS AS 'CERTIFICATE_HOLD'."
                    info_log.warning(f"\t\t\tWARNING: {warning}")
                    gpu_attestation_warning = warning
                elif ocsp_response.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
                    info_log.error(f"\t\t\tTHE {cert_chain[i].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value} certificate revocation status is UNKNOWN")
                    return False, gpu_attestation_warning
                else:
                    info_log.error(f"\t\t\tTHE {cert_chain[i].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value} IS REVOKED FOR REASON : {ocsp_response.revocation_reason}")
                    return False, gpu_attestation_warning

        if not revoked_status:
            info_log.info(f"\t\t\tThe certificate chain revocation status verification successful.")
        else:
            info_log.warning(f"\t\t\tThe certificate chain revocation status verification was not successful but continuing.")

        return True, gpu_attestation_warning

    @staticmethod
    def send_ocsp_request(data):
        """ A static method to prepare http request and send it to the ocsp server
        and returns the ocsp response message.

        Args:
            data (bytes): the raw ocsp request message.

        Returns:
            [cryptography.hazmat.backends.openssl.ocsp._OCSPResponse]: the ocsp response message object.
        """
        if not BaseSettings.OCSP_URL.lower().startswith('https'):
            # Raising exception in case of url not starting with http, and not FTP, etc.
            raise ValueError from None

        https_request = request.Request(BaseSettings.OCSP_URL, data)
        https_request.add_header("Content-Type", "application/ocsp-request")

        with request.urlopen(https_request) as https_response:      #nosec taken care of the security issue by checking for the url to start with "http"
            ocsp_response = ocsp.load_der_ocsp_response(https_response.read())

        return ocsp_response

    @staticmethod
    def verify_ocsp_signature(ocsp_response):
        """ A static method to perform the signature verification of the ocsp response message.

        Args:
            ocsp_response (cryptography.hazmat.backends.openssl.ocsp._OCSPResponse): the input ocsp response message object.

        Returns:
            [Bool]: returns True if the signature verification is successful, otherwise returns False.
        """
        try:
            signature = ocsp_response.signature
            data = ocsp_response.tbs_response_bytes
            leaf_certificate = ocsp_response.certificates[0]
            leaf_certificate.public_key().verify(signature, data, ec.ECDSA(SHA384()))
            return True

        except InvalidSignature:
            return False

        except Exception as error:
            err_msg = "Something went wrong during ocsp signature verification."
            info_log.error(error)
            info_log.info(err_msg)
            return False

    @staticmethod
    def fetch_rim_file(file_id):
        """ A static method to fetch the RIM file with the given file id from the RIM service.

        Args:
            file_id (str): the RIM file id which need to be fetched from the RIM service.

        Returns:
            [str]: the content of the required RIM file as a string.
        """
        try:
            event_log.debug(f"RIM URL is {BaseSettings.RIM_SERVICE_BASE_URL + file_id}")
            with request.urlopen(BaseSettings.RIM_SERVICE_BASE_URL + file_id) as https_response:
                data = https_response.read()
                json_object = json.loads(data)
                base64_data = json_object['rim']
                decoded_str = base64.b64decode(base64_data)
                return decoded_str.decode('utf-8')
        except HTTPError:
            info_log.error("Could not fetch RIM file from RIM service with id : " + file_id)
            sys.exit()

    @staticmethod
    def get_vbios_rim_file_id(project, project_sku, chip_sku, vbios_version):
        """ A static method to generate the required VBIOS RIM file id which needs to be fetched from the RIM service
            according to the vbios flashed onto the system.

        Args:
            attestation_report (AttestationReport): the object representing the attestation report.

        Returns:
            [str]: the VBIOS RIM file id.
        """
        base_str = 'NV_GPU_VBIOS_'

        return base_str + project + "_" + project_sku + "_" + chip_sku + "_" + vbios_version

    @staticmethod
    def get_driver_rim_file_id(driver_version):
        """ A static method to generate the driver RIM file id to be fetched from the RIM service corresponding to
            the driver installed onto the system.

        Args:
            driver_version (str): the driver version of the installed driver.

        Returns:
            [str]: the driver RIM file id.
        """
        base_str = 'NV_GPU_DRIVER_GH100_'
        return base_str + driver_version


    @staticmethod
    def get_vbios_rim_path(settings, attestation_report):
        """ A static method to determine the path of the appropriate VBIOS RIM file.

        Args:
            settings (config.HopperSettings): the object containing the various config info.
            attestation_report (AttestationReport): the object representing the attestation report

        Raises:
            RIMFetchError: it is raised in case the required VBIOS RIM file is not found.

        Returns:
            [str] : the path to the VBIOS RIM file.
        """
        project = attestation_report.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_PROJECT")
        project_sku = attestation_report.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_PROJECT_SKU")
        chip_sku = attestation_report.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_CHIP_SKU")
        vbios_version = format_vbios_version(attestation_report.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_VBIOS_VERSION"))
        vbios_version = vbios_version.replace(".", "").upper()

        project = project.decode('ascii').strip().strip('\x00')
        project = project.lower()
        project_sku = project_sku.decode('ascii').strip().strip('\x00')
        project_sku = project_sku.lower()
        chip_sku = chip_sku.decode('ascii').strip().strip('\x00')
        chip_sku = chip_sku.lower()

        rim_file_name = project + "_" + project_sku + "_" + chip_sku + "_" + vbios_version + "_" + settings.get_sku() + ".swidtag"
        list_of_files = os.listdir(settings.RIM_DIRECTORY_PATH)
        rim_path = os.path.join(settings.RIM_DIRECTORY_PATH, rim_file_name)

        if rim_file_name in list_of_files:
            return rim_path

        raise RIMFetchError(f"Could not find the required VBIOS RIM file : {rim_path}")

    @staticmethod
    def verify_attestation_report(attestation_report_obj, gpu_leaf_certificate, nonce, driver_version,
                                  vbios_version, settings):
        """ Performs the verification of the attestation report. This contains matching the nonce in the attestation report with
        the one generated by the cc admin, matching the driver version and vbios version in the attestation report with the one
        fetched from the driver. And then performing the signature verification of the attestation report.

        Args:
            attestation_report_obj (SpdmMeasurementResponseMessage): the object representing the attestation report.
            gpu_leaf_certificate (OpenSSL.crypto.X509): the gpu leaf attestation certificate.
            nonce (bytes): the nonce generated by the cc_admin.
            driver_version (str): the driver version fetched from the GPU.
            vbios_version (str): the vbios version fetched from the GPU.
            settings (config.HopperSettings): the object containing the various config info.

        Raises:
            NonceMismatchError: it is raised in case the nonce generated by cc admin does not match with the one in the attestation report.
            DriverVersionMismatchError: it is raised in case of the driver version does not matches with the one in the attestation report.
            VBIOSVersionMismatchError: it is raised in case of the vbios version does not matches with the one in the attestation report.
            SignatureVerificationError: it is raised in case the signature verification of the attestation report fails.

        Returns:
            [bool]: return True if the signature verification is successful.
        """
        assert isinstance(attestation_report_obj, AttestationReport)
        assert isinstance(gpu_leaf_certificate, crypto.X509)
        assert isinstance(nonce, bytes) and len(nonce) == settings.SIZE_OF_NONCE_IN_BYTES
        # Here the attestation report is the concatenated SPDM GET_MEASUREMENTS request with the SPDM GET_MEASUREMENT response message.
        request_nonce = attestation_report_obj.get_request_message().get_nonce()

        if len(nonce) > settings.SIZE_OF_NONCE_IN_BYTES or len(request_nonce) > settings.SIZE_OF_NONCE_IN_BYTES:
            err_msg = "\t\t Length of Nonce is greater than max nonce size allowed."
            event_log.error(err_msg)
            raise InvalidNonceError(err_msg)
        # compare the generated nonce with the nonce of SPDM GET MEASUREMENT request message in the attestation report.
        if request_nonce != nonce:
            err_msg = "\t\tThe nonce in the SPDM GET MEASUREMENT request message is not matching with the generated nonce."
            event_log.error(err_msg)
            raise NonceMismatchError(err_msg)
        else:
            info_log.info("\t\tThe nonce in the SPDM GET MEASUREMENT request message is matching with the generated nonce.")
            settings.mark_nonce_as_matching()

        # Checking driver version.
        driver_version_from_attestation_report = attestation_report_obj.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_DRIVER_VERSION")
        driver_version_from_attestation_report = driver_version_from_attestation_report.decode()

        if driver_version_from_attestation_report[-1] == '\0':
            driver_version_from_attestation_report = driver_version_from_attestation_report[:-1]

        info_log.info(f'\t\tDriver version fetched from the attestation report : {driver_version_from_attestation_report}')

        if driver_version_from_attestation_report != driver_version:
            err_msg = "\t\tThe driver version in attestation report is not matching with the driver version fetched from the driver."
            event_log.error(err_msg)
            raise DriverVersionMismatchError(err_msg)

        event_log.debug("Driver version in attestation report is matching.")
        settings.mark_attestation_report_driver_version_as_matching()

        # Checking vbios version.
        vbios_version_from_attestation_report = attestation_report_obj.get_response_message().get_opaque_data().get_data("OPAQUE_FIELD_ID_VBIOS_VERSION")
        vbios_version_from_attestation_report = format_vbios_version(vbios_version_from_attestation_report)
        info_log.info(f'\t\tVBIOS version fetched from the attestation report : {vbios_version_from_attestation_report}')

        if vbios_version_from_attestation_report != vbios_version:
            err_msg = "\t\tThe vbios version in attestation report is not matching with the vbios verison fetched from the driver."
            event_log.error(err_msg)
            raise VBIOSVersionMismatchError(err_msg)

        event_log.debug("VBIOS version in attestation report is matching.")
        settings.mark_attestation_report_vbios_version_as_matching()

        # Performing the signature verification.
        attestation_report_verification_status = attestation_report_obj.verify_signature(gpu_leaf_certificate.to_cryptography(),
                                                                                         settings.signature_length,
                                                                                         settings.HashFunction)
        if attestation_report_verification_status:
            info_log.info("\t\tAttestation report signature verification successful.")
            settings.mark_attestation_report_signature_verified()
        else:
            err_msg = "\t\tAttestation report signature verification failed."
            event_log.error(err_msg)
            raise SignatureVerificationError(err_msg)

        return attestation_report_verification_status

    @staticmethod
    def generate_nonce(size):
        """ Generates cryptographically strong nonce to be sent to the SPDM requester via the nvml api for the attestation report.

        Args:
            size (int): the number of random bytes to be generated.

        Returns:
            [bytes]: the bytes of length "size" generated randomly.
        """
        random_bytes = secrets.token_bytes(size)
        return random_bytes

    @staticmethod
    def validate_and_extract_nonce(nonce_hex_string):
        """ Validate and convert Nonce to bytes format

        Args:
            nonce_hex_string (string): 32 Bytes Nonce represented as Hex String

        Returns:
            [bytes]: Nonce represented as Bytes
        """
        if len(nonce_hex_string) == BaseSettings.SIZE_OF_NONCE_IN_HEX_STR and set(nonce_hex_string).issubset(string.hexdigits):
            return bytes.fromhex(nonce_hex_string)
        else :
            raise InvalidNonceError("Invalid Nonce Size. The nonce should be 32 bytes in length represented as Hex String")

    def __init__(self, number_of_gpus):
        """ It is the constructor for the CcAdminUtils.

        Args:
            number_of_gpus (int): The number of the available GPUs.
        """
        self.number_of_gpus = number_of_gpus