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

import argparse
import time
import logging
import sys
import base64

from verifier.attestation import AttestationReport
from verifier.rim import RIM
from verifier.nvml import (
    NvmlHandler,
    NvmlHandlerTest,
)
from verifier.verifier import Verifier
from verifier.config import (
    BaseSettings,
    HopperSettings,
    event_log,
    info_log,
    __author__,
    __copyright__,
    __version__,
)
from cryptography.x509.oid import NameOID
from verifier.exceptions import (
    Error,
    NoGpuFoundError,
    UnsupportedGpuArchitectureError,
    CertChainVerificationFailureError,
    AttestationReportVerificationError,
    RIMVerificationFailureError,
    UnknownGpuArchitectureError,
)
from verifier.cc_admin_utils import CcAdminUtils
from verifier.utils.claims_utils import ClaimsUtils
from verifier.utils import (
    function_wrapper_with_timeout,
    format_vbios_version,
)
from verifier.nvml.gpu_cert_chains import GpuCertificateChains

arguments_as_dictionary = None
previous_try_status = None
hwmodel = []
oemid = []
ueid = []
gpu_driver_attestation_warning_list = []
gpu_vbios_attestation_warning_list = []


def main():
    """ The main function for the CC admin tool.
    """
    global arguments_as_dictionary
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        help="Print more detailed output.",
        action="store_true",
    )
    parser.add_argument(
        "--test_no_gpu",
        help="""If there is no gpu and we
                need to test the verifier, then no nvml apis will be available so, the verifier
                will use a hardcoded gpu info.""",
        action="store_true",
    )
    parser.add_argument(
        "--driver_rim",
        help="The path to the driver RIM.",
    )
    parser.add_argument(
        "--vbios_rim",
        help="The path to the VBIOS RIM.",
    )
    parser.add_argument(
        "--user_mode",
        help="Runs the gpu attestation in user mode.",
        action="store_true",
    )
    parser.add_argument(
        "--allow_hold_cert",
        help="If the user wants to continue the attestation in case of the OCSP revocation status of the certificate "
             "in the RIM files is 'certificate_hold'.",
        action="store_true",
    )
    parser.add_argument(
        "--nonce",
        help="Nonce (32 Bytes) represented in Hex String format used for Attestation Report",
    )
    parser.add_argument(
        "--rim_root_cert",
        help="The path to the root cert to be used for the cert chain verification of the driver and vbios rim "
             "certificate chain.",
    )
    parser.add_argument(
        "--rim_service_url",
        help="If the user wants to override the RIM service base url and provide their own url, then can do so by "
             "passing it as a command line argument.",
    )
    parser.add_argument(
        "--ocsp_url",
        help="If the user wants to override the OCSP service url and provide their own url, then can do so by passing "
             "it as a command line argument.",
    )
    args = parser.parse_args()
    arguments_as_dictionary = vars(args)

    # nonce is generated / set if cc_admin is run as a standalone-tool
    if arguments_as_dictionary["test_no_gpu"]:
        nonce = BaseSettings.NONCE
    else:
        info_log.info("Generating nonce in the local GPU Verifier ..")
        nonce = CcAdminUtils.generate_nonce(BaseSettings.SIZE_OF_NONCE_IN_BYTES).hex()

    evidence_list = collect_gpu_evidence(nonce, arguments_as_dictionary['test_no_gpu'])
    result, _ = attest(arguments_as_dictionary, nonce, evidence_list)

    if not result:
        sys.exit(1)


def collect_gpu_evidence(nonce: str, no_gpu_mode=False, ppcie_mode=True):
    """ Method to Collect GPU Evidence used by Attestation SDK

    Args:
        nonce (String): Hex string representation of Nonce
        no_gpu_mode (Boolean): Represents if the function should run in No GPU (test) mode
        ppcie_mode (Boolean): Represents if the function should run in Standalone mode

    Returns:
        list of NVMLHandler objects containing GPU Evidence
    """
    info_log.debug("collect_gpu_evidence called")
    evidence_list = []

    try:
        if no_gpu_mode:
            event_log.info("Running in test_no_gpu mode.")
            evidence_nonce = BaseSettings.NONCE
            number_of_available_gpus = NvmlHandlerTest.get_number_of_gpus()

        else:
            init_nvml(ppcie_mode=ppcie_mode)
            evidence_nonce = CcAdminUtils.validate_and_extract_nonce(nonce)

            number_of_available_gpus = NvmlHandler.get_number_of_gpus()
            if number_of_available_gpus == 0:
                err_msg = "No GPU found"
                info_log.critical(err_msg)
                raise NoGpuFoundError(err_msg)

            info_log.info(f'Number of GPUs available : {number_of_available_gpus}')

        for i in range(number_of_available_gpus):
            info_log.info(f'Fetching GPU {i} information from GPU driver.')
            if no_gpu_mode:
                gpu_info_obj = NvmlHandlerTest(settings=BaseSettings)
            else:
                gpu_info_obj = NvmlHandler(index=i, nonce=evidence_nonce, settings=BaseSettings)
            evidence_list.append(gpu_info_obj)
        info_log.info("All GPU Evidences fetched successfully")
    except Exception as error:
        info_log.error(error)
    finally:
        return evidence_list


def collect_gpu_evidence_local(nonce: str, ppcie_mode: bool = True, no_gpu_mode=False, ):
    """ Method to Collect GPU Evidence for Local GPU Attestation workflow

    Args:
        nonce (String): Hex string representation of Nonce
        no_gpu_mode (Boolean): Represents if the function should run in No GPU (test) mode
        ppcie_mode (Boolean): Represents if the function should run in Standalone mode

    Returns:
        list of NVMLHandler objects containing GPU Evidence
    """
    return collect_gpu_evidence(nonce, no_gpu_mode, ppcie_mode)


def collect_gpu_evidence_remote(nonce: str, no_gpu_mode=False, ppcie_mode=True):
    """ Method to Collect GPU Evidence for Remote GPU Attestation workflow

    Args:
        nonce (String): Hex string representation of Nonce
        no_gpu_mode (Boolean): Represents if the function should run in No GPU (test) mode

    Returns:
        GPU Evidence list containing Base64 Encoded GPU certificate chain and Attestation Report as Hex String
    """
    evidence_list = collect_gpu_evidence(nonce, no_gpu_mode, ppcie_mode)
    remote_evidence_list = []
    for gpu_info_obj in evidence_list:
        gpu_cert_chain = gpu_info_obj.get_attestation_cert_chain()
        gpu_cert_chain_base64 = GpuCertificateChains.extract_gpu_cert_chain_base64(gpu_cert_chain)
        evidence_bytes = gpu_info_obj.get_attestation_report()
        evidence_base64 = base64.b64encode(evidence_bytes).decode("utf-8")
        gpu_evidence = {
            'certificate': gpu_cert_chain_base64,
            'evidence': evidence_base64,
        }
        remote_evidence_list.append(gpu_evidence)
    return remote_evidence_list


def init_nvml(ppcie_mode:bool):
    """ Method to Initialize NVML library
    """
    try:
        event_log.debug("Initializing the nvml library")
        NvmlHandler.init_nvml()

        # Ensuring that the system is running either in Confidential Compute mode or PPCIE mode
        if not NvmlHandler.is_cc_enabled() and not NvmlHandler.is_ppcie_mode_enabled():
            event_log.debug("The confidential compute is", NvmlHandler.is_cc_enabled(), "and the PPCIE mode is",
                            NvmlHandler.is_ppcie_mode_enabled())
            err_msg = ("The confidential compute feature and PPCIE mode is disabled !! Exiting now. Please enable one of "
                       "the feature and try again")
            info_log.error(err_msg)
            sys.exit()

        if NvmlHandler.is_ppcie_mode_enabled() and ppcie_mode:
            err_msg = ("Attestation Failed! Attestation in standalone mode is not supported for PPCIE system. Exiting "
                       "now.")
            info_log.error(err_msg)
            sys.exit()

        if NvmlHandler.is_cc_dev_mode():
            info_log.info("The system is running in CC DevTools mode !!")
    except Exception as error:
        info_log.error("Error occurred while initializing the NVML library. Error: %s", error)
        sys.exit()


def attest(arguments_as_dictionary, nonce, gpu_evidence_list):
    """ Method to perform GPU Attestation and return an Attestation Response.

    Args:
        arguments_as_dictionary (Dictionary): the dictionary object containing Attestation Options.

    Raises:
        Different Errors regarding GPU Attestation

    Returns:
        A tuple containing Attestation result (boolean) and Attestation JWT claims(JWT Object)
    """
    overall_status = False
    gpu_claims_list = []
    att_report_nonce_hex = CcAdminUtils.validate_and_extract_nonce(nonce)

    try:
        BaseSettings.allow_hold_cert = arguments_as_dictionary['allow_hold_cert']

        if not arguments_as_dictionary['rim_service_url'] is None:
            BaseSettings.set_rim_service_base_url(arguments_as_dictionary['rim_service_url'])

        if not arguments_as_dictionary['ocsp_url'] is None:
            BaseSettings.set_ocsp_url(arguments_as_dictionary['ocsp_url'])

        if arguments_as_dictionary['verbose']:
            info_log.setLevel(logging.DEBUG)

        for i, gpu_info_obj in enumerate(gpu_evidence_list):
            info_log.info("-----------------------------------")
            if gpu_info_obj.get_gpu_architecture() == 'HOPPER':
                event_log.debug(f'The architecture of the GPU with index {i} is HOPPER')
                settings = HopperSettings()

                HopperSettings.set_driver_rim_path(arguments_as_dictionary['driver_rim'])
                HopperSettings.set_vbios_rim_path(arguments_as_dictionary['vbios_rim'])

                if arguments_as_dictionary['test_no_gpu']:
                    HopperSettings.set_driver_rim_path(HopperSettings.TEST_NO_GPU_DRIVER_RIM_PATH)
                    HopperSettings.set_vbios_rim_path(HopperSettings.TEST_NO_GPU_VBIOS_RIM_PATH)
            else:
                err_msg = "Unknown GPU architecture."
                event_log.error(err_msg)
                raise UnknownGpuArchitectureError(err_msg)

            event_log.debug("GPU info fetched successfully.")

            info_log.info("Verifying GPU: %s", str(gpu_info_obj.get_uuid()))

            if gpu_info_obj.get_gpu_architecture() != settings.GpuArch:
                err_msg = "\tGPU architecture is not supported."
                event_log.error(err_msg)
                raise UnsupportedGpuArchitectureError(err_msg)

            event_log.debug("\tGPU architecture is correct.")
            settings.mark_gpu_arch_is_correct()

            driver_version = gpu_info_obj.get_driver_version()
            vbios_version = gpu_info_obj.get_vbios_version()
            vbios_version = vbios_version.lower()

            info_log.info(f'\tDriver version fetched : {driver_version}')
            info_log.info(f'\tVBIOS version fetched : {vbios_version}')
            settings.mark_gpu_driver_version(driver_version)
            settings.mark_gpu_vbios_version(vbios_version)

            event_log.debug(f'GPU info fetched : \n\t\t{vars(gpu_info_obj)}')

            # Parsing the attestation report.
            attestation_report_data = gpu_info_obj.get_attestation_report()
            attestation_report_obj = AttestationReport(attestation_report_data, settings)
            settings.mark_attestation_report_parsed()

            info_log.info("\tValidating GPU certificate chains.")
            gpu_attestation_cert_chain = gpu_info_obj.get_attestation_cert_chain()

            for certificate in gpu_attestation_cert_chain:
                cert = certificate.to_cryptography()
                issuer = cert.issuer.public_bytes()
                subject = cert.subject.public_bytes()
                if issuer == subject:
                    event_log.debug("Root certificate is a available.")
            if len(gpu_attestation_cert_chain) > 1:
                common_name = \
                gpu_attestation_cert_chain[1].to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                    0].value
                hwmodel.append(common_name)
                ueid.append(gpu_attestation_cert_chain[0].get_serial_number())

            gpu_leaf_cert = (gpu_attestation_cert_chain[0])
            event_log.debug("\t\tverifying attestation certificate chain.")
            cert_verification_status = CcAdminUtils.verify_gpu_certificate_chain(gpu_attestation_cert_chain, settings,
                                                                                 attestation_report_obj.get_response_message().get_opaque_data().get_data(
                                                                                     "OPAQUE_FIELD_ID_FWID").hex())

            if not cert_verification_status:
                err_msg = "\t\tGPU attestation report certificate chain validation failed."
                event_log.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)
            else:
                info_log.info("\t\tGPU attestation report certificate chain validation successful.")

            cert_chain_revocation_status, gpu_attestation_warning = CcAdminUtils.ocsp_certificate_chain_validation(
                gpu_attestation_cert_chain,
                settings,
                BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION)

            if not cert_chain_revocation_status:
                err_msg = "\t\tGPU attestation report certificate chain revocation validation failed."
                event_log.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)

            settings.mark_gpu_attestation_report_cert_chain_validated()

            info_log.info("\tAuthenticating attestation report")
            attestation_report_obj.print_obj(info_log)
            attestation_report_verification_status = CcAdminUtils.verify_attestation_report(
                attestation_report_obj=attestation_report_obj,
                gpu_leaf_certificate=gpu_leaf_cert,
                nonce=att_report_nonce_hex,
                driver_version=driver_version,
                vbios_version=vbios_version,
                settings=settings)
            if attestation_report_verification_status:
                info_log.info("\t\tAttestation report verification successful.")
            else:
                err_msg = "\t\tAttestation report verification failed."
                event_log.error(err_msg)
                raise AttestationReportVerificationError(err_msg)

            info_log.info("\tAuthenticating the RIMs.")

            # performing the schema validation and signature verification of the driver RIM.
            info_log.info("\t\tAuthenticating Driver RIM")

            if arguments_as_dictionary['driver_rim'] is None:

                if not arguments_as_dictionary['test_no_gpu']:
                    info_log.info("\t\t\tFetching the driver RIM from the RIM service.")
                    try:
                        driver_rim_file_id = CcAdminUtils.get_driver_rim_file_id(driver_version)

                        driver_rim_content = function_wrapper_with_timeout([CcAdminUtils.fetch_rim_file,
                                                                            driver_rim_file_id,
                                                                            'fetch_rim_file'],
                                                                           BaseSettings.MAX_NETWORK_TIME_DELAY)

                        driver_rim = RIM(rim_name='driver', settings=settings, content=driver_rim_content)
                    except Exception as error:
                        info_log.error("Error occurred while fetching the driver RIM from the "
                                       "RIM service due to %s", error)
                        sys.exit()
                else:
                    info_log.info("\t\t\tUsing the local driver rim file : " + settings.DRIVER_RIM_PATH)
                    driver_rim = RIM(rim_name='driver', settings=settings, rim_path=settings.DRIVER_RIM_PATH)

            else:
                info_log.info("\t\t\tUsing the local driver rim file : " + settings.DRIVER_RIM_PATH)
                driver_rim = RIM(rim_name='driver', settings=settings, rim_path=settings.DRIVER_RIM_PATH)
            oemid.append(driver_rim.get_manufacturer_id(driver_rim_content))
            driver_rim_verification_status, gpu_driver_attestation_warning = driver_rim.verify(version=driver_version,
                                                                                               settings=settings)
            gpu_driver_attestation_warning_list.append(gpu_driver_attestation_warning)
            if driver_rim_verification_status:
                settings.mark_driver_rim_signature_verified()
                info_log.info("\t\t\tDriver RIM verification successful")
            else:
                event_log.error("\t\t\tDriver RIM verification failed.")
                raise RIMVerificationFailureError("\t\t\tDriver RIM verification failed.\n\t\t\tQuitting now.")

            # performing the schema validation and signature verification of the vbios RIM.
            info_log.info("\t\tAuthenticating VBIOS RIM.")
            vbios_rim_path = settings.VBIOS_RIM_PATH

            if arguments_as_dictionary['vbios_rim'] is None:

                if not arguments_as_dictionary['test_no_gpu']:
                    info_log.info("\t\t\tFetching the VBIOS RIM from the RIM service.")

                    project = attestation_report_obj.get_response_message().get_opaque_data().get_data(
                        "OPAQUE_FIELD_ID_PROJECT")
                    project_sku = attestation_report_obj.get_response_message().get_opaque_data().get_data(
                        "OPAQUE_FIELD_ID_PROJECT_SKU")
                    chip_sku = attestation_report_obj.get_response_message().get_opaque_data().get_data(
                        "OPAQUE_FIELD_ID_CHIP_SKU")
                    vbios_version = format_vbios_version(
                        attestation_report_obj.get_response_message().get_opaque_data().get_data(
                            "OPAQUE_FIELD_ID_VBIOS_VERSION"))
                    vbios_version_for_id = vbios_version.replace(".", "").upper()
                    vbios_version = vbios_version.lower()

                    project = project.decode('ascii').strip().strip('\x00')
                    project = project.upper()
                    project_sku = project_sku.decode('ascii').strip().strip('\x00')
                    project_sku = project_sku.upper()
                    chip_sku = chip_sku.decode('ascii').strip().strip('\x00')
                    chip_sku = chip_sku.upper()
                    try:
                        vbios_rim_file_id = CcAdminUtils.get_vbios_rim_file_id(project,
                                                                               project_sku,
                                                                               chip_sku,
                                                                               vbios_version_for_id)
                        event_log.debug(f"vbios_rim_file_id is {vbios_rim_file_id}")
                        vbios_rim_content = function_wrapper_with_timeout([CcAdminUtils.fetch_rim_file,
                                                                           vbios_rim_file_id,
                                                                           'fetch_rim_file'],
                                                                          BaseSettings.MAX_NETWORK_TIME_DELAY)

                        vbios_rim = RIM(rim_name='vbios', settings=settings, content=vbios_rim_content)
                    except Exception as error:
                        info_log.error("Error occurred while fetching the vbios RIM from the "
                                       "RIM service due to %s", error)
                        sys.exit()

                else:
                    info_log.info("\t\t\tUsing the TEST_NO_GPU VBIOS rim file.")
                    vbios_rim_path = settings.TEST_NO_GPU_VBIOS_RIM_PATH
                    vbios_rim = RIM(rim_name='vbios', settings=settings, rim_path=vbios_rim_path)

            else:
                info_log.info("\t\t\tUsing the vbios from the local disk : " + arguments_as_dictionary['vbios_rim'])
                vbios_rim = RIM(rim_name='vbios', settings=settings, rim_path=arguments_as_dictionary['vbios_rim'])

            vbios_rim_verification_status, gpu_attestation_warning = vbios_rim.verify(version=vbios_version,
                                                                                      settings=settings)
            gpu_vbios_attestation_warning_list.append(gpu_attestation_warning)
            if vbios_rim_verification_status:
                settings.mark_vbios_rim_signature_verified()
                info_log.info("\t\t\tVBIOS RIM verification successful")
            else:
                event_log.error("\t\tVBIOS RIM verification failed.")
                raise RIMVerificationFailureError("\t\tVBIOS RIM verification failed.\n\tQuitting now.")

            verifier_obj = Verifier(attestation_report_obj, driver_rim, vbios_rim, settings=settings)
            verifier_obj.verify(settings)

            if settings.check_status():
                info_log.info(f'\tGPU {i} with UUID {gpu_info_obj.get_uuid()} verified successfully.')
            else:
                info_log.info(f'The verification of GPU {i} with UUID {gpu_info_obj.get_uuid()} resulted in failure.')

            if i == 0:
                overall_status = settings.check_status()
            else:
                overall_status = overall_status and settings.check_status()

            # set current gpu_claims
            gpu_claims_list.append(ClaimsUtils.get_current_gpu_claims(settings, gpu_info_obj.get_uuid()))

    except Exception as error:
        info_log.error(error)
        # Retry will be re-implemented / enabled for HGX PPCIE GA
        # if is_non_fatal_issue(error):
        #   retry(nonce)
        # set error claims
        gpu_claims_list.append(ClaimsUtils.get_current_gpu_claims(settings, gpu_info_obj.get_uuid()))
    finally:
        # Checking the attestation status.
        if overall_status:
            if not arguments_as_dictionary["user_mode"] and not arguments_as_dictionary['test_no_gpu']:
                if not NvmlHandler.get_gpu_ready_state():
                    info_log.info("\tSetting the GPU Ready State to READY")
                    NvmlHandler.set_gpu_ready_state(True)
                else:
                    info_log.info("\tGPU Ready State is already READY")

            info_log.info(f'GPU Attestation is Successful.')
        elif arguments_as_dictionary['test_no_gpu']:
            pass
        else:
            info_log.info(f'GPU Attestation failed.')
            gpu_state = False
            ready_str = 'NOT READY'
            if NvmlHandler.is_cc_dev_mode():
                info_log.info('\tGPU is running in DevTools mode!!')
                gpu_state = True
                ready_str = 'READY'
            if not arguments_as_dictionary["user_mode"]:
                if NvmlHandler.get_gpu_ready_state() != gpu_state:
                    info_log.info(f'\tSetting the GPU Ready State to {ready_str}')
                    NvmlHandler.set_gpu_ready_state(gpu_state)
                else:
                    info_log.info(f'\tGPU Ready state is already {ready_str}')

        jwt_claims = ClaimsUtils.create_detached_eat_claims(overall_status, gpu_claims_list, nonce, hwmodel, oemid,
                                                            ueid, gpu_driver_attestation_warning_list,
                                                            gpu_vbios_attestation_warning_list)
        event_log.debug("-----------------------------------")
        event_log.debug("-----------ENDING-----------")
        return overall_status, jwt_claims


def retry(nonce):
    """ This function is used to retry the GPU attestation again in case of occurrence of
    certain types of exceptions.
    """
    global arguments_as_dictionary

    # Clean-up
    NvmlHandler.close_nvml()

    if BaseSettings.is_retry_allowed():
        info_log.info("Retrying the GPU attestation.")
        evidence_list = collect_gpu_evidence(nonce)
        result, _ = attest(arguments_as_dictionary, nonce, evidence_list)
        time.sleep(BaseSettings.MAX_TIME_DELAY)
    else:
        gpu_state = False
        ready_str = 'NOT READY'
        init_nvml()
        if NvmlHandler.is_cc_dev_mode():
            info_log.info('\tGPU is running in DevTools mode!!')
            gpu_state = True
            ready_str = 'READY'
        if not arguments_as_dictionary["user_mode"]:
            if NvmlHandler.get_gpu_ready_state() != gpu_state:
                info_log.info(f'\tSetting the GPU Ready State to {ready_str}')
                NvmlHandler.set_gpu_ready_state(gpu_state)
            else:
                info_log.info(f'\tGPU Ready state is already {ready_str}')


if __name__ == "__main__":
    main()
