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

import logging
import base64
import sys


from .nscq import NSCQHandler
from .config import (
    BaseSettings,
)
from .models.nvswitch import NVSwitch
from .nvswitch_admin_utils import NVSwitchAdminUtils
from .attestation import AttestationReport
from .config import LS10Settings
from .exceptions import *
from .rim import RIM
from .utils.claims_utils import ClaimsUtils
from .utils.cert_chain_utils import extract_switch_cert_chain_base64
from nv_attestation_sdk.utils.logging_config import get_logger
from nv_attestation_sdk.verifiers.nv_switch_verifier.utils import (
    format_vbios_version,
    function_wrapper_with_timeout, )
from .nvswitch_verifier import SwitchVerifier
from cryptography.x509.oid import NameOID

args = None
previous_try_status = None
logger = get_logger()
hwmodel = []
ueid = []
switch_attestation_warning_list = []


def collect_evidence_remote(nonce: str, ppcie_mode: bool):
    evidence_list = collect_evidence(nonce, ppcie_mode)
    remote_evidence_list = []
    for evidence_obj in evidence_list:
        switch_cert_chain_base64 = extract_switch_cert_chain_base64(evidence_obj.attestation_cert_chain)
        evidence_bytes = evidence_obj.attestation_report
        evidence_base64 = base64.b64encode(evidence_bytes).decode("utf-8")
        switch_evidence = {
            'certificate': switch_cert_chain_base64,
            'evidence': evidence_base64,
        }
        remote_evidence_list.append(switch_evidence)
    return remote_evidence_list


def collect_evidence(nonce: str, ppcie_mode: bool):
    """ Method to Collect nvSwitch Evidence used by Attestation SDK for Local and Remote nvSwitch Attestation.

    Args:
        nonce (String): Hex string representation of Nonce
        ppcie_mode (Boolean): Flag to indicate ppcie mode for user to run without any other verifier
    Returns:
        Switch Evidence list containing Base64 Encoded Switch certificate chain and Attestation Report as Hex String
    """
    if ppcie_mode:
        logger.error("Attestation failed as switch attestation is not supported in ppcie mode")
        sys.exit()
    logger.debug("collect_evidence called")
    evidence_list = []

    try:
        nscq_handler = NSCQHandler()
        if nonce:
            logger.debug("Using the user provided nonce")
            evidence_nonce = NVSwitchAdminUtils.validate_and_extract_nonce(nonce)

        switch_uuid, rc = nscq_handler.get_all_switch_uuid()
        logger.debug("Number of NVSwitches are: %d", len(switch_uuid))
        if len(switch_uuid) == 0:
            err_msg = "No Switch found"
            logger.critical(err_msg)
            raise NoSwitchFoundError(err_msg)

        for uuid in switch_uuid:
            logger.info("Getting evidence details for %s", uuid)
            switch_att_report, rc = nscq_handler.get_switch_attestation_report(uuid, evidence_nonce)
            switch_cert_chain = nscq_handler.get_switch_attestation_certificate_chain(uuid)
            switch_report_obj = NVSwitch(uuid, switch_cert_chain, switch_att_report)
            evidence_list.append(switch_report_obj)

        logger.info("All nvSwitch Evidences fetched successfully")

    except Exception as error:
        logger.error(error)

    finally:
        return evidence_list


def attest(args, nonce, evidence_list):
    """ Method to perform nvSwitch Attestation and return an Attestation Response.

    supported args:
        --verbose
        --vbios_rim
        --allow_hold_cert
        --nonce
        --rim_root_cert
    	--rim_service_url
        --ocsp_url

    Args:
        args (Dictionary): the dictionary object containing Attestation Options.

    Raises:
        Different Errors regarding Switch Attestation

    Returns:
        A tuple containing Attestation result (boolean) and Attestation JWT claims(JWT Object)
    """
    overall_status = False
    claims_list = []
    att_report_nonce_hex = NVSwitchAdminUtils.validate_and_extract_nonce(nonce)
    switch_uuid = ""
    settings = LS10Settings()

    try:
        BaseSettings.allow_hold_cert = args['allow_hold_cert']

        if not args['rim_service_url'] is None:
            BaseSettings.set_rim_service_base_url(args['rim_service_url'])

        if not args['ocsp_url'] is None:
            BaseSettings.set_ocsp_url(args['ocsp_url'])

        for i, evidence_obj in enumerate(evidence_list):
            switch_uuid = evidence_obj.uuid
            logger.info("-----------------------------------")
            logger.info(f'Verifying Switch : {i}')
            nscq_handler = NSCQHandler()
            if nscq_handler.get_switch_architecture()[0] != settings.SwitchArch:
                err_msg = "\tSwitch architecture is not supported."
                logger.error(err_msg)
                raise UnsupportedSwitchException(err_msg)
            logger.debug("\tSwitch architecture is correct.")


            settings = LS10Settings()
            settings.mark_switch_arch_is_correct()

            logger.info("NVSwitch info fetched successfully.")
            logger.debug(f'Switch info fetched : \n\t\t{vars(evidence_obj)}')

            # Parsing the attestation report.
            attestation_report_obj = AttestationReport(evidence_obj.attestation_report, logger, logger)
            settings.mark_attestation_report_parsed()



            # driver_version = attestation_report_obj.get_response_message().get_opaque_data().get_data(
            #                                                                                "OPAQUE_FIELD_ID_DRIVER_VERSION").hex()
            vbios_version_bytes = attestation_report_obj.get_response_message().get_opaque_data().get_data(
                                                                                           "OPAQUE_FIELD_ID_VBIOS_VERSION")
            vbios_version = vbios_version_bytes.decode('utf-8')


            settings.mark_bios_version(vbios_version)



            logger.info("\tValidating Switch certificate chains.")
            switch_attestation_cert_chain = evidence_obj.attestation_cert_chain

            for certificate in switch_attestation_cert_chain:
                cert = certificate.to_cryptography()
                issuer = cert.issuer.public_bytes()
                subject = cert.subject.public_bytes()

                if issuer == subject:
                    logger.debug("Root certificate is a available.")

            if len(switch_attestation_cert_chain) > 1:
                common_name = switch_attestation_cert_chain[1].to_cryptography().subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                hwmodel.append(common_name)
                ueid.append(switch_attestation_cert_chain[0].get_serial_number())

            switch_leaf_cert = (switch_attestation_cert_chain[0])
            logger.debug("\t\tverifying attestation certificate chain.")
            cert_verification_status = NVSwitchAdminUtils.verify_switch_certificate_chain(switch_attestation_cert_chain,
                                                                                          settings,
                                                                                          attestation_report_obj.get_response_message().get_opaque_data().get_data(
                                                                                           "OPAQUE_FIELD_ID_FWID").hex())

            if not cert_verification_status:
                err_msg = "\t\tnvSwitch attestation report certificate chain validation failed."
                logger.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)
            else:
                logger.info("\t\tnvSwitch attestation report certificate chain validation successful.")

            cert_chain_revocation_status, switch_attestation_warning = NVSwitchAdminUtils.ocsp_certificate_chain_validation(
                switch_attestation_cert_chain,
                settings,
                BaseSettings.Certificate_Chain_Verification_Mode.SWITCH_ATTESTATION)


            if not cert_chain_revocation_status:
                err_msg = "\t\tnvSwitch attestation report certificate chain revocation validation failed."
                logger.error(err_msg)
                raise CertChainVerificationFailureError(err_msg)

            settings.mark_switch_attestation_report_cert_chain_as_validated()

            logger.info("\tAuthenticating attestation report")
            attestation_report_obj.print_obj(logger)
            attestation_report_verification_status = NVSwitchAdminUtils.verify_attestation_report(
                attestation_report_obj=attestation_report_obj,
                switch_leaf_certificate=switch_leaf_cert,
                nonce=att_report_nonce_hex,
                vbios_version=vbios_version,
                settings=settings)
            if attestation_report_verification_status:
                logger.info("\t\tAttestation report verification successful.")
            else:
                err_msg = "\t\tAttestation report verification failed."
                logger.error(err_msg)
                raise AttestationReportVerificationError(err_msg)

            logger.info("\tAuthenticating the RIMs.")

            # performing the schema validation and signature verification of the vbios RIM.
            logger.info("\t\tAuthenticating VBIOS RIM.")
            vbios_rim_path = settings.VBIOS_RIM_PATH

            if args['vbios_rim'] is None:
                logger.info("\t\t\tFetching the VBIOS RIM from the RIM service.")
                vbios_version = format_vbios_version(
                    attestation_report_obj.get_response_message().get_opaque_data().get_data(
                        "OPAQUE_FIELD_ID_VBIOS_VERSION"))
                vbios_version_for_id = vbios_version.replace(".", "").upper()
                vbios_version = vbios_version.lower()

                # NV_SWITCH_BIOS_5612_0002_890_9610550001
                project = settings.PROJECT
                project_sku = settings.PROJECT_SKU
                chip_sku = settings.CHIP_SKU
                try:

                    vbios_rim_file_id = NVSwitchAdminUtils.get_vbios_rim_file_id(project,
                                                                                 project_sku,
                                                                                 chip_sku,
                                                                                 vbios_version_for_id)

                    vbios_rim_content = function_wrapper_with_timeout([NVSwitchAdminUtils.fetch_rim_file,
                                                                       vbios_rim_file_id,
                                                                       'fetch_rim_file'],
                                                                      logger,
                                                                      BaseSettings.MAX_NETWORK_TIME_DELAY)
                    vbios_rim = RIM(rim_name='vbios', settings=settings, info_logger=logger,
                                    debug_logger=logger,
                                    content=vbios_rim_content)
                except Exception as error:
                    logger.error("Failed to fetch Vbios RIM file from RIM service due to: %s", error)
                    logger.error(f'The verification of nvSwitch {i} resulted in failure.')
                    overall_status = False
                    sys.exit()
            else:
                logger.info("\t\t\tUsing the vbios from the local disk : " + args['vbios_rim'])
                vbios_rim = RIM(rim_name='vbios', settings=settings, rim_path=args['vbios_rim'])

            vbios_rim_verification_status, switch_attestation_warning = vbios_rim.verify(version=vbios_version, settings=settings)
            switch_attestation_warning_list.append(switch_attestation_warning)
            if vbios_rim_verification_status:
                settings.mark_vbios_rim_signature_verified()
                logger.info("\t\t\tVBIOS RIM verification successful")
            else:
                logger.error("\t\tVBIOS RIM verification failed.")
                raise RIMVerificationFailureError("\t\tVBIOS RIM verification failed.\n\tQuitting now.")

            verifier_obj = SwitchVerifier(attestation_report_obj, vbios_rim, settings=settings)
            verifier_obj.verify(settings)

            # Checking the attestation status.
            if settings.check_status():
                logger.info(f'\tnvSwitch {i} verified successfully.')
            else:
                logger.info(f'The verification of nvSwitch {i} resulted in failure.')

            if i == 0:
                overall_status = settings.check_status()
            else:
                overall_status = overall_status and settings.check_status()

            # set current gpu_claims
            claims = ClaimsUtils.get_current_switch_claims(settings, switch_uuid)
            logger.debug(f"switch UUID: {switch_uuid} Claims: {claims}")
            claims_list.append(claims)
    except Exception as error:
        logger.error(error)

        # set error claims
        claims_list.append(ClaimsUtils.get_current_switch_claims(settings, switch_uuid))
    finally:
        if overall_status:
            logger.info(f"All nvSwitches Attested Successfully")
        else:
            logger.info(f"nvSwitch Attestation failed")
        jwt_claims = ClaimsUtils.create_detached_eat_claims(overall_status, claims_list, nonce, hwmodel, ueid, switch_attestation_warning_list)
        logger.debug("-----------------------------------")
        logger.debug("-----------ENDING-----------")
        return overall_status, jwt_claims


if __name__ == "__main__":
    main()
