#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""Main class that performs end to end workflow orchestration among different dependant modules"""
import base64
import json
import os
import secrets
import sys
import argparse

from nv_attestation_sdk import attestation

from nv_attestation_sdk.verifiers.nv_switch_verifier.nscq import NSCQHandler
from verifier.nvml import NvmlHandler

from nv_attestation_sdk.verifiers.nv_switch_verifier.models.nvswitch import NVSwitch
from .src.exceptions.exception import (
    PpcieVerifierException,
    GpuPreChecksException,
    SwitchPreChecksException,
    GpuAttestationException,
    SwitchAttestationException,
)
from .src.utils.status import Status
from .src.topology.validate_topology import TopologyValidation
from .src.nvml.nvml_client import NvmlClient
from .src.utils.logging import setup_logging, get_logger
from .src.utils.config import REMOTE_GPU_VERIFIER_SERVICE_URL, REMOTE_NVSWITCH_VERIFIER_SERVICE_URL

parser = argparse.ArgumentParser()
logger = setup_logging()


def verification():
    """
    This function is the start of PPCIE verification tool.
    It performs the end to end workflow orchestration among different
    dependant modules to verify the GPUs/NvSwitches are
    present in a correct state.

    """
    global logger
    status = Status()
    try:
        parser.add_argument(
            "--gpu-attestation-mode",
            help="Configurable GPU attestation mode as LOCAL or REMOTE",
            required=True,
            choices=["LOCAL", "REMOTE"],
        )
        parser.add_argument(
            "--switch-attestation-mode",
            help="Configurable Switch attestation mode as LOCAL or REMOTE",
            required=True,
            choices=["LOCAL", "REMOTE"],
        )
        parser.add_argument(
            "--log",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "TRACE", "CRITICAL"],
            help="Define log level Example --log=DEBUG",
        )
        args = vars(parser.parse_args())
        logger = get_logger(args["log"])

        logger.info("PPCIE: Starting PPCIE Verification Tool")
        nvml_client = NvmlClient()
        logger.debug("PPCIE: Initializing NSCQ driver")
        nscq_client = NSCQHandler()

        number_of_gpus = get_number_of_gpus(logger, nvml_client)
        switch_list_uuids = get_number_of_switches(logger, nscq_client)
        number_of_switches = len(switch_list_uuids)
        if number_of_gpus != 8 and number_of_switches != 4:
            logger.error("PPCIE: Number of GPUs present are : %d and Switches are %d which do not meet the required "
                         "configuration. Exiting..", number_of_gpus, number_of_switches)
            sys.exit()
        if args["gpu_attestation_mode"] != args["switch_attestation_mode"]:
            logger.error(
                "PPCIE: GPU attestation mode and Switch attestation mode should be same. Exiting..")
            sys.exit()

        status = validate_gpu_pre_checks(nvml_client, logger, status)
        if status.gpu_pre_checks is True:
            status = validate_switch_pre_checks(
                nscq_client, logger, status, switch_list_uuids
            )
            if status.switch_pre_checks is True:
                status, gpu_attestation_report = perform_gpu_attestation(
                    args["gpu_attestation_mode"], logger, status
                )
                if status.gpu_attestation is True:
                    status, switch_attestation_report = perform_switch_attestation(
                        args["switch_attestation_mode"], logger, status
                    )
                    if status.switch_attestation is True:
                        topology = TopologyValidation()
                        status = topology.gpu_topology_check(
                            gpu_attestation_report, number_of_switches, status
                        )
                        if status.topology_checks is not False:
                            status = topology.switch_topology_check(
                                switch_attestation_report, number_of_gpus, status
                            )
                            if status.topology_checks is True:
                                # Setting the gpu ready state if all stages have passed
                                enable_gpu_state(logger, nvml_client)
                                status.ppcie_successful = True
        # If any of the stages fail, we disable the GPU ready state
        if not status.ppcie_successful:
            disable_gpu_state(logger, nvml_client)
        else:
            logger.debug("PPCIE: All stages have passed")
        nvml_client.__destroy__()
    except Exception as e:
        logger.error("An error occurred while using the PPCIE Verification Tool %s", e)
    finally:
        status.status(logger)
        logger.info("PPCIE: End of PPCIE Verification Tool")


def disable_gpu_state(logger, nvml_client):
    """
    Disables the GPU ready state if it is already set.
    Args:
        logger (Logger): Logger object for logging messages.
        nvml_client (NvmlClient): NvmlClient object for interacting with NVML library.
    Returns:
        None
    """
    if nvml_client.get_gpu_ready_state() != 0:
        logger.debug("PPCIE: Disabling GPU ready state since it is already set")
        gpu_state = nvml_client.set_gpu_ready_state(False)
        logger.debug("PPCIE: GPU state is: %s", gpu_state)
    else:
        logger.info("PPCIE: GPU state is NOT READY")


def enable_gpu_state(logger, nvml_client):
    """
    Enables the GPU ready state if it is not already set.
    Args:
        logger (Logger): Logger object for logging messages.
        nvml_client (NvmlClient): NvmlClient object for interacting with NVML library.
    Returns:
        None
    """
    if nvml_client.get_gpu_ready_state() != 1:
        gpu_state = nvml_client.set_gpu_ready_state(True)
        logger.debug("PPCIE: GPU state is: %s", gpu_state)
    else:
        logger.info("PPCIE: GPU state is READY")


def get_number_of_switches(logger, nscq_client):
    """
    This function finds the number of NVSwitches available in the system.
    :param logger:
    :param nscq_client:
    :return: list of switch uuids
    """
    switch_list_uuids = nscq_client.get_all_switch_uuid()[0]
    logger.info("PPCIE: Number of NVSwitches are: %d", len(switch_list_uuids))
    if switch_list_uuids is not None and len(switch_list_uuids) == 0:
        logger.error("PPCIE: There are no switches available in the system. Exiting..")
        sys.exit()
    return switch_list_uuids


def get_number_of_gpus(logger, nvml_client):
    """
    This function finds the number of GPUs available in the system.
    :param logger:
    :param nvml_client:
    :return: number of GPUs available in the system
    """
    logger.debug("PPCIE: Finding the number of GPUs")
    number_of_gpus = nvml_client.get_number_of_gpus()
    logger.info("PPCIE: Number of GPUs are: %d", number_of_gpus)
    if number_of_gpus == 0 or number_of_gpus is None or number_of_gpus < 0:
        logger.error("PPCIE: There are no GPUs available in the system. Exiting..")
        sys.exit()
    return number_of_gpus


def generate_nonce():
    """
    This function generates the nonce for the attestation client.
    """
    random_bytes = secrets.token_bytes(32)
    return random_bytes.hex()


def perform_gpu_attestation(attestation_mode, logger, status):
    """
    This function performs the GPU attestation.

    Args:
        attestation_mode (str): Configurable GPU attestation mode as LOCAL or REMOTE.
        :param logger:
        :param status:
    """
    try:
        logger.debug("PPCIE: Calling Attestation SDK to attest the GPUs")
        client = attestation.Attestation()
        client.set_nonce(generate_nonce())
        client.set_name("HGX-node")
        logger.debug("PPCIE: Node name: %s", client.get_name())
        client.add_verifier(
            attestation.Devices.GPU,
            attestation.Environment[attestation_mode],
            REMOTE_GPU_VERIFIER_SERVICE_URL,
            "",
        )
        logger.debug("PPCIE: Collecting evidences for the GPU")
        evidence_list = client.get_evidence(ppcie_mode=False)
        gpu_attestation_report = []

        # Appending the gpu attestation report in hex format
        for evidence in evidence_list:
            if isinstance(evidence, NvmlHandler):
                # Process nvmlhandler object when LOCAL attestation
                gpu_attestation_report.append(evidence.AttestationReport)
            elif isinstance(evidence, dict):
                # Process dict object when REMOTE attestation
                evidence_bytes = base64.b64decode(evidence.get("evidence"))
                gpu_attestation_report.append(evidence_bytes)
            else:
                logger.error(
                    "PPCIE: Invalid/Unknown evidence type found for GPU %s",
                    type(evidence),
                )
                status.gpu_attestation = False
                sys.exit()

        logger.info("PPCIE: Attesting the GPUs")
        gpu_attestation_result = client.attest(evidence_list)
        logger.info("PPCIE: GPU Attestation result: %s", gpu_attestation_result)
        if gpu_attestation_result:
            status.gpu_attestation = True
        else:
            status.gpu_attestation = False
        file = "data/NVGPU" + attestation_mode.capitalize() + "Policy.json"
        with open(
                os.path.join(os.path.dirname(__file__), file), encoding="utf-8"
        ) as json_file:
            json_data = json.load(json_file)
            att_result_policy = json.dumps(json_data)
        logger.debug(
            "PPCIE: GPU Attestation Token validation result: %s",
            client.validate_token(att_result_policy),
        )
        client.clear_verifiers()
    except Exception as e:
        status.gpu_attestation = False
        logger.error("PPCIE: An error occurred while attesting the GPUs %s", e)
        sys.exit()
    logger.info("PPCIE: GPU Attestation Completed")
    return status, gpu_attestation_report


def validate_gpu_pre_checks(nvml_client, logger, status):
    """
    This function performs the GPU pre-checks.

    Args:
        nvml_client: NvmlClient object
        logger: Logger object
        status: Status object
    """
    try:
        logger.debug("PPCIE: Finding the TNVL Mode of the GPU:")
        system_settings, status = nvml_client.get_system_conf_compute_settings(status)
        if system_settings.multiGpuMode == 1:
            logger.debug("PPCIE: All GPUs have TNVL enabled")
            status.gpu_pre_checks = True
        else:
            logger.error(
                "PPCIE: Terminating the process as TNVL is not enabled for all the GPUs"
            )
            status.gpu_pre_checks = False
            sys.exit()
    except Exception as e:
        status.gpu_pre_checks = False
        logger.error("PPCIE: An error occurred while checking GPU pre checks %s", e)
        sys.exit()
    return status


def perform_switch_attestation(switch_attestaion_mode, logger, status):
    """
    This function performs the switch attestation.

    Args:
        switch_attestaion_mode (str): Configurable switch attestation mode as LOCAL or REMOTE.
        :param status:
        :param logger:
    """
    try:
        logger.debug("PPCIE: Calling Attestation SDK to attest the Switches")
        switch_attester = attestation.Attestation()
        switch_attester.set_name("HGX-node")
        switch_attester.set_nonce(generate_nonce())
        logger.debug("PPCIE: Node name: %s", switch_attester.get_name())
        switch_attester.add_verifier(
            attestation.Devices.SWITCH,
            attestation.Environment[switch_attestaion_mode],
            REMOTE_NVSWITCH_VERIFIER_SERVICE_URL,
            "",
        )
        switch_attestation_report = []
        evidence_list = switch_attester.get_evidence(ppcie_mode=False)
        for evidence in evidence_list:
            if isinstance(evidence, NVSwitch):
                # Process nvmlhandler object when LOCAL attestation
                switch_attestation_report.append(evidence.attestation_report)
            elif isinstance(evidence, dict):
                # Process dict object when REMOTE attestation
                evidence_bytes = base64.b64decode(evidence.get("evidence"))
                switch_attestation_report.append(evidence_bytes)
            else:
                logger.error(
                    "PPCIE: Invalid/Unknown evidence type found for switch %s",
                    type(evidence),
                )
                status.switch_attestation = False
                sys.exit()

        logger.info("PPCIE: Attesting the switches")
        attestation_result = switch_attester.attest(evidence_list)
        if attestation_result:
            status.switch_attestation = True
        else:
            status.switch_attestation = False
        logger.info("PPCIE: Switch attestation result is %s", attestation_result)
        file = "data/NVSwitch" + switch_attestaion_mode.capitalize() + "Policy.json"
        with open(
                os.path.join(os.path.dirname(__file__), file), encoding="utf-8"
        ) as json_file:
            json_data = json.load(json_file)
            att_result_policy = json.dumps(json_data)
        logger.debug(
            "PPCIE: Switch Attestation Token validation result %s",
            switch_attester.validate_token(att_result_policy),
        )

        logger.info("PPCIE: Switch Attestation Completed")
    except Exception as e:
        logger.error("PPCIE: An error occurred while attesting the switches %s", e)
        status.switch_attestation = False
        sys.exit()
    return status, switch_attestation_report


def validate_switch_pre_checks(nscq_client, logger, status, switch_uuid_list):
    """
    This function performs the switch pre-checks.

    Args:
        nscq_client: NSCQHandler object
        logger: Logger object
        status: Status object
    """
    try:
        for uuid in switch_uuid_list:
            tnvl_status, rc = nscq_client.is_switch_tnvl_mode(uuid)
            logger.debug(
                "PPCIE: TNVL Mode of the switch is: %s with return "
                "code of calling function: %d",
                tnvl_status,
                rc,
            )
            if tnvl_status != 1:
                logger.error(
                    "PPCIE: TNVL mode for the switch with id %sis not enabled. Exiting..",
                    uuid,
                )
                status.switch_pre_checks = False
                sys.exit()
            lock_status, rc = nscq_client.is_switch_lock_mode(uuid)
            logger.debug(
                "PPCIE: Lock Mode of the switch is: %s with return "
                "code of calling function: %d",
                lock_status,
                rc,
            )
            if lock_status != 1:
                logger.error(
                    "PPCIE: Lock mode for the switch with id %s is not enabled. Exiting..",
                    uuid,
                )
                status.switch_pre_checks = False
                sys.exit()
        status.switch_pre_checks = True
    except Exception as e:
        status.switch_pre_checks = False
        logger.error(
            "PPCIE: An exception has occurred while attempting to check switch pre checks %s",
            e,
        )
        sys.exit()
    return status


if __name__ == "__main__":
    verification()
