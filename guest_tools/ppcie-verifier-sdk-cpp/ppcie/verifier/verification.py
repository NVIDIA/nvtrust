# SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Main class that performs end to end workflow orchestration among different dependant modules"""
import base64
import json
import os
import secrets
import sys
import argparse
import logging
import subprocess
import tempfile

from .src.utils.status import Status
from .src.topology.validate_topology import TopologyValidation
from .src.nvml.nvml_client import NvmlClient
from .src.utils.logging import setup_logging, get_logger
from .src.nscq import NSCQHandler

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
            "--nonce",
            help="Nonce for the attestation (in hex format). If not provided, a nonce will be generated.",
            type=str
        )
        parser.add_argument(
            "--verifier",
            help="Verifier type ('local' or 'remote')",
            choices=["local", "remote"]
        )
        parser.add_argument(
            "--gpu-evidence",
            help="Path to a local file which contains GPU evidence. Used instead of calling NVML",
            type=str
        )
        parser.add_argument(
            "--switch-evidence",
            help="Path to a local file which contains Switch evidence. Used instead of calling NSCQ",
            type=str
        )
        parser.add_argument(
            "--relying-party-policy",
            help="Path to a local file which contains a Relying Party Rego policy",
            type=str
        )
        parser.add_argument(
            "--rim-url",
            help="The URL to be used for fetching driver and VBIOS RIM files",
            type=str
        )
        parser.add_argument(
            "--ocsp-url",
            help="The URL to be used for checking the revocation status of a certificate",
            type=str
        )
        parser.add_argument(
            "--nras-url",
            help="Base URL for the NVIDIA Remote Attestation Service",
            type=str
        )
        parser.add_argument(
            "--log-level",
            choices=["trace", "debug", "info", "warn", "error", "off"],
            default="warn",
            help="Define log level (default: warn). Example --log-level=debug"
        )
        parser.add_argument(
            "--service-key",
            help="Service key used to authenticate remote service calls to attestation services",
            type=str
        )
        args = vars(parser.parse_args())
        # Map CLI-friendly levels to Python logging levels
        requested_level = args["log_level"].lower()
        level_map = {
            "trace": logging.DEBUG,
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warn": logging.WARNING,
            "error": logging.ERROR,
            "off": logging.CRITICAL,
        }
        logger = get_logger(level_map[requested_level])
        if requested_level == "off":
            logger.disabled = True

        if not args.get("nonce"):
            args["nonce"] = generate_nonce()
            logger.debug("PPCIE: Generated nonce for attestation")

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

        status = validate_gpu_pre_checks(nvml_client, logger, status)
        if status.gpu_pre_checks is True:
            status = validate_switch_pre_checks(
                nscq_client, logger, status, switch_list_uuids
            )
            if status.switch_pre_checks is True:
                status, gpu_attestation_report = perform_gpu_attestation(
                    logger, status, args
                )
                if status.gpu_attestation is True:
                    status, switch_attestation_report = perform_switch_attestation(
                        logger, status, args
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
        depth = 0
        while e:
            indent = "  " * depth
            cause = f"Caused by:" if e.__cause__ else ""
            logger.error(f"{indent}{type(e).__name__}: {str(e)}. {cause}")
            e = e.__cause__
            depth += 1
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

def run_nvattest_command(logger, command, description):
    """
    Runs an nvattest subprocess command, captures and logs output and exit code.
    Args:
        logger: Logger object
        command: List[str] full command to execute
        description: str, short name of the operation for logging (e.g., 'collect-evidence' or 'attest')
    Returns:
        Tuple[str, int]: (stdout_text, exit_code)
    """
    logger.debug("PPCIE: Running %s command: %s", description, " ".join(command))
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    stdout_output = completed.stdout or ""
    stderr_output = completed.stderr or ""
    exit_code = completed.returncode
    
    logger.debug("PPCIE: nvattest %s exit code: %d", description, exit_code)
    logger.debug("PPCIE: nvattest %s stderr: %s", description, stderr_output)
    logger.debug("PPCIE: nvattest %s stdout: %s", description, stdout_output)
    
    return stdout_output, exit_code


def extract_last_json_object(text):
    """Extract the last balanced JSON object from noisy text output.
    """
    if not text:
        raise json.JSONDecodeError("Empty output", text, 0)

    end_pos = None
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        c = text[i]
        if c == '}':
            if end_pos is None:
                end_pos = i
            depth += 1
        elif c == '{' and depth > 0:
            depth -= 1
            if depth == 0 and end_pos is not None:
                candidate = text[i:end_pos + 1]
                return json.loads(candidate)

    raise json.JSONDecodeError("No JSON object found in output", text, 0)

def perform_gpu_attestation(logger, status, args):
    """
    This function performs the GPU attestation.

    Args:
        :param logger:
        :param status:
        :param args: Dictionary of arguments to perform GPU attestation
    """
    try:
        logger.debug("PPCIE: Calling Attestation SDK to attest the GPUs")
        gpu_attestation_report = []

        log_level = args.get("log_level")
        nonce = args.get("nonce")
        verifier = args.get("verifier")
        gpu_evidence = args.get("gpu_evidence")
        relying_party_policy = args.get("relying_party_policy")
        rim_url = args.get("rim_url")
        ocsp_url = args.get("ocsp_url")
        nras_url = args.get("nras_url")
        service_key = args.get("service_key")

        # ---- Step 1: get evidence items (from file or collect-evidence) ----
        evidence_items = []
        temp_gpu_evidence_file = None
        
        if gpu_evidence:
            logger.debug("PPCIE: Loading GPU evidence from file: %s", gpu_evidence)
            with open(gpu_evidence, "r", encoding="utf-8") as f:
                evidence_items = json.load(f)
            if not isinstance(evidence_items, list):
                logger.error("PPCIE: GPU evidence file format invalid; expected list")
                status.gpu_attestation = False
                sys.exit()
        else:
            logger.debug("PPCIE: Collecting GPU evidence from NVML")
            nvattest_collect_evidence_cmd = ["nvattest"]
            if log_level: nvattest_collect_evidence_cmd.extend(["--log-level", log_level])
            nvattest_collect_evidence_cmd.extend([
                "collect-evidence",
                "--device", "gpu",
                "--format", "json",
            ])
            if nonce: nvattest_collect_evidence_cmd.extend(["--nonce", nonce])

            collect_output, collect_exit_code = run_nvattest_command(
                logger, nvattest_collect_evidence_cmd, "collect-evidence"
            )

            if collect_exit_code != 0:
                logger.error("PPCIE: collect-evidence failed with non-zero exit code %d", collect_exit_code)
                status.gpu_attestation = False      
                sys.exit()

            try:
                collect_json = extract_last_json_object(collect_output)
                evidence_items = collect_json.get("evidences") or []
                
                # Save collected evidence to a temporary file to pass to attest command
                temp_gpu_evidence_fd, temp_gpu_evidence_file = tempfile.mkstemp(suffix='.json', prefix='gpu_evidence_')
                with os.fdopen(temp_gpu_evidence_fd, 'w') as f:
                    json.dump(evidence_items, f)
                logger.debug("PPCIE: Saved collected GPU evidence to temporary file: %s", temp_gpu_evidence_file)
                gpu_evidence = temp_gpu_evidence_file
                
            except json.JSONDecodeError as jde:
                logger.error("PPCIE: Failed to parse collect-evidence JSON: %s", jde)
                status.gpu_attestation = False
                sys.exit()

        # Decode all items into gpu_attestation_report
        for item in evidence_items:
            encoded_evidence = item.get("evidence")
            try:
                decoded_evidence = base64.b64decode(encoded_evidence)
            except Exception as decode_err:
                logger.error("PPCIE: Failed to decode GPU evidence: %s", decode_err)
                status.gpu_attestation = False
                sys.exit()
            gpu_attestation_report.append(decoded_evidence)

        # ---- Step 2: attest ----
        nvattest_attest_cmd = [
            "nvattest"
        ]
        if log_level: nvattest_attest_cmd.extend(["--log-level", log_level])
        nvattest_attest_cmd.extend([
            "attest",
            "--device", "gpu",
            "--format", "json",
        ])
        if nonce: nvattest_attest_cmd.extend(["--nonce", nonce])
        if verifier: nvattest_attest_cmd.extend(["--verifier", verifier])
        if gpu_evidence: nvattest_attest_cmd.extend(["--gpu-evidence-source", "file", "--gpu-evidence-file", gpu_evidence])
        if relying_party_policy: nvattest_attest_cmd.extend(["--relying-party-policy", relying_party_policy])
        if rim_url: nvattest_attest_cmd.extend(["--rim-url", rim_url])
        if ocsp_url: nvattest_attest_cmd.extend(["--ocsp-url", ocsp_url])
        if nras_url: nvattest_attest_cmd.extend(["--nras-url", nras_url])
        if service_key: nvattest_attest_cmd.extend(["--service-key", service_key])

        attest_output, attest_exit_code = run_nvattest_command(
            logger, nvattest_attest_cmd, "attest"
        )

        if attest_exit_code == 0:
            status.gpu_attestation = True
        else:
            logger.error("PPCIE: nvattest attest command failed with non-zero exit code %d", attest_exit_code)
            status.gpu_attestation = False

    except Exception as e:
        status.gpu_attestation = False
        logger.error("PPCIE: An error occurred while attesting the GPUs %s", e)
        sys.exit()
    finally:
        # Clean up temporary evidence file if created
        if temp_gpu_evidence_file and os.path.exists(temp_gpu_evidence_file):
            try:
                os.remove(temp_gpu_evidence_file)
                logger.debug("PPCIE: Removed temporary GPU evidence file: %s", temp_gpu_evidence_file)
            except Exception as cleanup_err:
                logger.warning("PPCIE: Failed to remove temporary GPU evidence file: %s", cleanup_err)
    
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
            logger.error("PPCIE: Terminating the process as TNVL is not enabled for all the GPUs")
            status.gpu_pre_checks = False
            sys.exit()
    except Exception as e:
        status.gpu_pre_checks = False
        logger.error("PPCIE: An error occurred while checking GPU pre checks %s", e)
        sys.exit()
    return status


def perform_switch_attestation(logger, status, args):
    """
    This function performs the switch attestation.

    Args:
        :param status:
        :param logger:
        :param args: Dictionary of arguments to perform NVSwitch attestation
    """
    try:
        logger.debug("PPCIE: Calling Attestation SDK to attest the NVSwitches")
        switch_attestation_report = []

        log_level = args.get("log_level")
        nonce = args.get("nonce")
        verifier = args.get("verifier")
        switch_evidence = args.get("switch_evidence")
        relying_party_policy = args.get("relying_party_policy")
        rim_url = args.get("rim_url")
        ocsp_url = args.get("ocsp_url")
        nras_url = args.get("nras_url")
        service_key = args.get("service_key")

        # ---- Step 1: get evidence items (from file or collect-evidence) ----
        evidence_items = []
        temp_switch_evidence_file = None
        
        if switch_evidence:
            logger.debug("PPCIE: Loading switch evidence from file: %s", switch_evidence)
            with open(switch_evidence, "r", encoding="utf-8") as f:
                evidence_items = json.load(f)
            if not isinstance(evidence_items, list):
                logger.error("PPCIE: Switch evidence file format invalid; expected list")
                status.switch_attestation = False
                sys.exit()
        else:
            logger.debug("PPCIE: Collecting switch evidence from NSCQ")
            nvattest_collect_evidence_cmd = ["nvattest"]
            if log_level: nvattest_collect_evidence_cmd.extend(["--log-level", log_level])
            nvattest_collect_evidence_cmd.extend([
                "collect-evidence",
                "--device", "nvswitch",
                "--format", "json",
            ])
            if nonce: nvattest_collect_evidence_cmd.extend(["--nonce", nonce])

            collect_output, collect_exit_code = run_nvattest_command(
                logger, nvattest_collect_evidence_cmd, "collect-evidence"
            )

            if collect_exit_code != 0:
                logger.error("PPCIE: collect-evidence failed with non-zero exit code %d", collect_exit_code)
                status.switch_attestation = False      
                sys.exit()

            try:
                collect_json = extract_last_json_object(collect_output)
                evidence_items = collect_json.get("evidences") or []
                
                # Save collected evidence to a temporary file to pass to attest command
                temp_switch_evidence_fd, temp_switch_evidence_file = tempfile.mkstemp(suffix='.json', prefix='switch_evidence_')
                with os.fdopen(temp_switch_evidence_fd, 'w') as f:
                    json.dump(evidence_items, f)
                logger.debug("PPCIE: Saved collected switch evidence to temporary file: %s", temp_switch_evidence_file)
                switch_evidence = temp_switch_evidence_file
                
            except json.JSONDecodeError as jde:
                logger.error("PPCIE: Failed to parse collect-evidence JSON: %s", jde)
                status.switch_attestation = False
                sys.exit()

        # Decode all items into switch_attestation_report
        for item in evidence_items:
            encoded_evidence = item.get("evidence")
            try:
                decoded_evidence = base64.b64decode(encoded_evidence)
            except Exception as decode_err:
                logger.error("PPCIE: Failed to decode Switch evidence: %s", decode_err)
                status.switch_attestation = False
                sys.exit()
            switch_attestation_report.append(decoded_evidence)

        # ---- Step 2: attest ----
        nvattest_attest_cmd = [
            "nvattest"
        ]
        if log_level: nvattest_attest_cmd.extend(["--log-level", log_level])
        nvattest_attest_cmd.extend([
            "attest",
            "--device", "nvswitch",
            "--format", "json",
        ])
        if nonce: nvattest_attest_cmd.extend(["--nonce", nonce])
        if verifier: nvattest_attest_cmd.extend(["--verifier", verifier])
        if switch_evidence: nvattest_attest_cmd.extend(["--nvswitch-evidence-source", "file", "--nvswitch-evidence-file", switch_evidence])
        if relying_party_policy: nvattest_attest_cmd.extend(["--relying-party-policy", relying_party_policy])
        if rim_url: nvattest_attest_cmd.extend(["--rim-url", rim_url])
        if ocsp_url: nvattest_attest_cmd.extend(["--ocsp-url", ocsp_url])
        if nras_url: nvattest_attest_cmd.extend(["--nras-url", nras_url])
        if service_key: nvattest_attest_cmd.extend(["--service-key", service_key])

        attest_output, attest_exit_code = run_nvattest_command(
            logger, nvattest_attest_cmd, "attest"
        )

        if attest_exit_code == 0:
            status.switch_attestation = True
        else:
            logger.error("PPCIE: nvattest attest command failed with non-zero exit code %d", attest_exit_code)
            status.switch_attestation = False

    except Exception as e:
        status.switch_attestation = False
        logger.error("PPCIE: An error occurred while attesting the NVSwitches %s", e)
        sys.exit()
    finally:
        # Clean up temporary evidence file if created
        if temp_switch_evidence_file and os.path.exists(temp_switch_evidence_file):
            try:
                os.remove(temp_switch_evidence_file)
                logger.debug("PPCIE: Removed temporary switch evidence file: %s", temp_switch_evidence_file)
            except Exception as cleanup_err:
                logger.warning("PPCIE: Failed to remove temporary switch evidence file: %s", cleanup_err)
    
    logger.info("PPCIE: NVSwitch Attestation Completed")
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
