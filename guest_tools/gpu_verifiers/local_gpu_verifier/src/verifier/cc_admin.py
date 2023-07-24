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
import jwt
import json

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
from verifier.exceptions import (
    Error,
    RIMFetchError,
    NoGpuFoundError,
    UnsupportedGpuArchitectureError,
    CertChainVerificationFailureError,
    AttestationReportVerificationError,
    RIMVerificationFailureError,
    UnknownGpuArchitectureError,
)
from verifier.exceptions.utils import (
    is_non_fatal_issue,
    need_to_change_gpu_state,
)
from verifier.cc_admin_utils import CcAdminUtils


def main():
    """ The main function for the CC admin tool.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-v",
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
        default="/usr/share/nvidia/rim/RIM_GH100PROD.swidtag"
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
    args = parser.parse_args()
    arguments_as_dictionary = vars(args)
    return attest(arguments_as_dictionary)


def attest(arguments_as_dictionary):
    """ Method to perform GPU Attestation and return an Attestation Response.

    Args:
        arguments_as_dictionary (Dictionary): the dictionary object containing Attestation Options.

    Raises:
        Different Errors regarding GPU Attestation

    Returns:
        A tuple containing Attestation result (boolean) and Attestation JWT claims(JWT Object)
    """
    overall_status = False
    verified_claims = {}
    try:

        if arguments_as_dictionary['verbose']:
            info_log.setLevel(logging.DEBUG)

        if arguments_as_dictionary['test_no_gpu']:
            event_log.info("Running in test_no_gpu mode.")
            number_of_available_gpus = NvmlHandlerTest.get_number_of_gpus()
        else:
            event_log.debug("Initializing the nvml library")
            NvmlHandler.init_nvml()

            if not NvmlHandler.is_cc_enabled():
                err_msg = "The confidential compute feature is disabled !!\nQuitting now."
                raise Error(err_msg)

            if NvmlHandler.is_cc_dev_mode():
                info_log.info("The system is running in CC DevTools mode !!")
            number_of_available_gpus = NvmlHandler.get_number_of_gpus()

        if number_of_available_gpus == 0:
            err_msg = "No GPU found"
            info_log.critical(err_msg)
            raise NoGpuFoundError(err_msg)

        BaseSettings.mark_gpu_as_available()

        info_log.info(f'Number of GPUs available : {number_of_available_gpus}')

        for i in range(number_of_available_gpus):
            info_log.info("-----------------------------------")
            info_log.info(f'Fetching GPU {i} information from GPU driver.')
            nonce_for_attestation_report = CcAdminUtils.generate_nonce(BaseSettings.SIZE_OF_NONCE_IN_BYTES)

            if arguments_as_dictionary['test_no_gpu']:
                nonce_for_attestation_report = BaseSettings.NONCE
                gpu_info_obj = NvmlHandlerTest(settings=BaseSettings)
            else:
                gpu_info_obj = NvmlHandler(index=i, nonce=nonce_for_attestation_report, settings=BaseSettings)

            if gpu_info_obj.get_gpu_architecture() == 'HOPPER':
                event_log.debug(f'The architecture of the GPU with index {i} is HOPPER')
                settings = HopperSettings()

                if arguments_as_dictionary['driver_rim'] is None and not arguments_as_dictionary['test_no_gpu']:
                    raise RIMFetchError("Driver RIM file path not provided!!")

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
            settings.mark_gpu_info_fetched()

            info_log.info(f'VERIFYING GPU : {i}')

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

            event_log.debug(f'GPU info fetched : \n\t\t{vars(gpu_info_obj)}')

            info_log.info("\tValidating GPU certificate chains.")
            gpu_attestation_cert_chain = gpu_info_obj.get_attestation_cert_chain()

            for certificate in gpu_attestation_cert_chain:
                cert = certificate.to_cryptography()
                issuer = cert.issuer.public_bytes()
                subject = cert.subject.public_bytes()

                if issuer == subject:
                    event_log.debug("Root certificate is a available.")
                    settings.mark_root_cert_available()

            gpu_leaf_cert = (gpu_attestation_cert_chain[0])
            event_log.debug("\t\tverifying attestation certificate chain.")
            cert_verification_status = CcAdminUtils.verify_certificate_chain(gpu_attestation_cert_chain,
                                                                             settings,
                                                                             BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION)

            if not cert_verification_status:
                err_msg = "\t\tGPU attestation report certificate chain validation failed."
                event_log.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)
            else:
                settings.mark_gpu_cert_chain_verified()
                info_log.info("\t\tGPU attestation report certificate chain validation successful.")

            cert_chain_revocation_status = CcAdminUtils.ocsp_certificate_chain_validation(gpu_attestation_cert_chain,
                                                                                          settings,
                                                                                          BaseSettings.Certificate_Chain_Verification_Mode.GPU_ATTESTATION)

            if not cert_chain_revocation_status:
                err_msg = "\t\tGPU attestation report certificate chain revocation validation failed."
                event_log.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)

            settings.mark_gpu_cert_check_complete()

            info_log.info("\tAuthenticating attestation report")
            attestation_report_data = gpu_info_obj.get_attestation_report()
            attestation_report_obj = AttestationReport(attestation_report_data, settings)
            attestation_report_obj.print_obj(info_log)
            settings.mark_attestation_report_parsed()
            attestation_report_verification_status = CcAdminUtils.verify_attestation_report(
                attestation_report_obj=attestation_report_obj,
                gpu_leaf_certificate=gpu_leaf_cert,
                nonce=nonce_for_attestation_report,
                driver_version=driver_version,
                vbios_version=vbios_version,
                settings=settings)
            if attestation_report_verification_status:
                settings.mark_attestation_report_verified()
                info_log.info("\t\tAttestation report verification successful.")
            else:
                err_msg = "\t\tAttestation report verification failed."
                event_log.error(err_msg)
                raise AttestationReportVerificationError(err_msg)

            # performing the schema validation and signature verification if the driver RIM.
            info_log.info("\tAuthenticating the RIMs.")
            info_log.info("\t\tAuthenticating Driver RIM")
            driver_rim = RIM(settings.DRIVER_RIM_PATH, rim_name='driver', settings=settings)
            driver_rim_verification_status = driver_rim.verify(version=driver_version, settings=settings)

            if driver_rim_verification_status:
                settings.mark_driver_rim_signature_verified()
                info_log.info("\t\t\tDriver RIM verification successful")
            else:
                event_log.error("\t\t\tDriver RIM verification failed.")
                raise RIMVerificationFailureError("\t\t\tDriver RIM verification failed.\n\t\t\tQuitting now.")

            # performing the schema validation and signature verification if the vbios RIM.
            info_log.info("\t\tAuthenticating VBIOS RIM.")
            vbios_rim_path = settings.VBIOS_RIM_PATH

            if arguments_as_dictionary["vbios_rim"] is None and not arguments_as_dictionary['test_no_gpu']:
                vbios_rim_path = CcAdminUtils.get_vbios_rim_path(settings, attestation_report_obj)

            vbios_rim = RIM(vbios_rim_path, rim_name='vbios', settings=settings)
            vbios_rim_verification_status = vbios_rim.verify(version=vbios_version, settings=settings)

            if vbios_rim_verification_status:
                settings.mark_vbios_rim_signature_verified()
                info_log.info("\t\t\tVBIOS RIM verification successful")
            else:
                event_log.error("\t\tVBIOS RIM verification failed.")
                raise RIMVerificationFailureError("\t\tVBIOS RIM verification failed.\n\tQuitting now.")

            verifier_obj = Verifier(attestation_report_obj, driver_rim, vbios_rim, settings=settings)
            verifier_obj.verify(settings)

            # Checking the attestation status.
            if settings.check_status():

                if not arguments_as_dictionary["user_mode"] and not arguments_as_dictionary['test_no_gpu']:
                    info_log.info("\tSetting the GPU Ready State to READY.")
                    NvmlHandler.set_gpu_ready_state(True)

                info_log.info(f'\tGPU {i} verified successfully.')

            elif arguments_as_dictionary['test_no_gpu']:
                pass
            else:
                if not NvmlHandler.is_cc_dev_mode() and not arguments_as_dictionary["user_mode"]:
                    info_log.info("\tSetting the GPU Ready State to NOT READY.")
                    NvmlHandler.set_gpu_ready_state(False)
                elif NvmlHandler.is_cc_dev_mode() and not arguments_as_dictionary["user_mode"]:
                    info_log.info("\tSetting the GPU Ready State to READY as the system is in DEV mode.")
                    NvmlHandler.set_gpu_ready_state(True)

                info_log.info(f'The verification of GPU {i} resulted in failure.')

            if i == 0:
                overall_status = settings.check_status()
            else:
                overall_status = overall_status and settings.check_status()

    except Exception as error:
        info_log.error(error)

        if arguments_as_dictionary['test_no_gpu']:
            return

        if is_non_fatal_issue(error):
            retry(error, arguments_as_dictionary["user_mode"])

        elif need_to_change_gpu_state(error):
            if not NvmlHandler.is_cc_dev_mode() and not arguments_as_dictionary["user_mode"]:
                info_log.info("\tSetting the GPU Ready State to NOT READY.")
                NvmlHandler.set_gpu_ready_state(False)
            elif NvmlHandler.is_cc_dev_mode() and not arguments_as_dictionary["user_mode"]:
                info_log.info("\tSetting the GPU Ready State to READY as the system is in DEV mode.")
                NvmlHandler.set_gpu_ready_state(True)

    finally:
        event_log.debug("-----------------------------------")
        if overall_status:
            info_log.info(f"\tGPU Attested Successfully")
        else:
            info_log.info(f"\tGPU Attestation failed")

        # check status and update the claims list in the finally block such that
        # un-checked claims will be false in case of exceptions

        if 'gpu_info_obj' in locals():
            settings.check_status()
            verified_claims = settings.claims
            verified_claims['x-nv-gpu-uuid'] = gpu_info_obj.get_uuid()
        else:
            verified_claims = {}
        formatted_claims_str = json.dumps(verified_claims, indent=2)
        event_log.debug(f"\tGPU Verified claims list : {formatted_claims_str}")
        event_log.debug("-----------------------------------")
        jwt_claims = create_jwt_token(verified_claims)
        return overall_status, jwt_claims
        event_log.debug("-----------ENDING-----------")


def create_jwt_token(gpu_claims_list: any):
    """ Method to create a JWT token from JSON claims object
    Args:
        gpu_claims_list: list of Attestation Claims in JSON.
    Returns:
        JWT token that corresponds to the Claims.
    """
    encoded_data = jwt.encode(gpu_claims_list,
                              'secret',
                              "HS256")
    return encoded_data


def retry(error, is_user_mode):
    """ This function is used to retry the GPU attestation again in case of occurrence of
    certain types of exceptions.

    Args:
        error (exceptions.Error): The exception that have occurred.
        is_user_mode (bool): If the cc_admin tool is being used in user_mode then it does not
                             changes the gpu ready state.
    """
    # Clean-up
    NvmlHandler.close_nvml()

    if BaseSettings.is_retry_allowed():
        time.sleep(BaseSettings.MAX_TIME_DELAY)
        info_log.info("Retrying the GPU attestation.")
        main()
    elif need_to_change_gpu_state(error) and not is_user_mode and not NvmlHandler.is_cc_dev_mode():
        info_log.info("Setting the GPU Ready State to not Ready.")
        NvmlHandler.set_gpu_ready_state(False)


if __name__ == "__main__":
    main()