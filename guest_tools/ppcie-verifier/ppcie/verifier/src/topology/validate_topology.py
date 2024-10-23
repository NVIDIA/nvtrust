#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

""" This module contains the code to validate the topology of the GPUs and NvSwitches """

import sys

from verifier.config import HopperSettings
from verifier import attestation

from nv_attestation_sdk.verifiers.nv_switch_verifier.attestation import (
    AttestationReport,
)
from ..topology.exceptions import (
    GpuTopologyValidationError,
    SwitchTopologyValidationError,
)
from ..utils.logging import get_logger

logger = get_logger()

GpuAttestationReport = attestation.AttestationReport
SwitchAttestationReport = AttestationReport

def read_field_as_little_endian(binary_data):
    """ Reads a multi-byte field in little endian form and return the read
    field as a hexadecimal string.

    Args:
        binary_data (bytes): the data to be read in little endian format.

    Returns:
        [str]: the value of the field as hexadecimal string.
    """
    assert type(binary_data) is bytes
    x= str()

    for i in range(len(binary_data)):
        temp = binary_data[i : i + 1]
        x = temp.hex() + x

    return x

def split_to_hex_array(string, number_of_gpus):
    "Splits a string into an array of substrings of the given length."
    arr = []
    for i in range(0, 18 * number_of_gpus, 8):
        substring = string[i : i + 8]
        arr.append(substring[::-1].hex())
    return arr


class TopologyValidation:
    """
    Validates the topology of the GPUs and NvSwitches
    """

    def __init__(self):
        self.opaque_data_field = {}
        self.unique_switches = set()
        self.unique_gpus = set()

    def switch_topology_check(
        self, switch_attestation_report_list, number_of_gpus, status
    ):
        """
        Validates from the switch attestation report whether every switch is connected to unique GPUs
        :param switch_attestation_report_list:
        :param number_of_gpus:
        :param status:
        return status
        """
        try:
            logger.debug("Performing Switch topology check")
            if len(switch_attestation_report_list) != 4:
                logger.error("PPCIE: Switch Topology check failed: We do not have the required "
                             "number of evidences in attestation report instead found %d evidences", len(switch_attestation_report_list))
                status.topology_checks = False
                sys.exit()
            for report in switch_attestation_report_list:
                attestation_report = SwitchAttestationReport(report, logger, logger)
                switch_pdi = (
                    attestation_report.get_response_message()
                    .get_opaque_data()
                    .get_data("OPAQUE_FIELD_ID_DEVICE_PDI")
                    .hex()
                )
                if switch_pdi not in self.unique_switches:
                    logger.error(
                        "PPCIE: Switch Topology check: The switch PDI reported in switch attestation report which is %s is "
                        "different than expected PDIs in gpu attestation report %s. Topology check failed", switch_pdi, self.unique_switches
                    )
                    status.topology_checks = False
                    sys.exit()
                gpu_pdis = (
                    attestation_report.get_response_message()
                    .get_opaque_data()
                    .get_data("OPAQUE_FIELD_ID_SWITCH_GPU_PDIS")
                )
                gpu_pdis = set(gpu_pdis)
                number_of_gpus = 8
                if len(self.unique_gpus) == 0:
                    self.unique_gpus = gpu_pdis
                if len(gpu_pdis) != number_of_gpus:
                    logger.error(
                        "PPCIE: Switch Topology check: Switches are not connected to the expected number of GPUs "
                        "which are %d but found %d instead. Topology check failed for switches",
                        number_of_gpus,
                        len(gpu_pdis),
                    )
                    status.topology_checks = False
                    sys.exit()
                elif self.unique_gpus != gpu_pdis:
                    logger.error(
                        "PPCIE: We do not have unique GPUs connected to every Switch... Topology check failed for Switches. Unique GPUs from switch attestation report are %s and the next iteration found different in the same report %s", self.unique_gpus, gpu_pdis
                    )
                    sys.exit()
        except Exception as e:
            status.topology_checks = False
            logger.error(
                "PPCIE: Topology check failed for Switch due to exception: %s", e
            )
            sys.exit()
        status.topology_checks = True
        logger.debug("Switch topology check completed")
        return status

    def gpu_topology_check(
        self, gpu_attestation_report_list, number_of_switches, status
    ):
        """
        Validates from the gpu_attestation_report_list whether every GPU is connected to unique number of switches
        :param gpu_attestation_report_list:
        :param number_of_switches:
        :param status:
        return status
        """
        try:
            logger.debug("PPCIE: Performing GPU topology check")
            settings = HopperSettings()
            if len(gpu_attestation_report_list) != 8:
                logger.error("PPCIE: GPU Topology check failed: We do not have the required "
                             "number of evidences in attestation report instead found %d evidences", len(gpu_attestation_report_list))
                status.topology_checks = False
                sys.exit()
            for evidence in gpu_attestation_report_list:
                attestation_report_obj = GpuAttestationReport(evidence, settings)
                switch_pdis_in_evidence = (
                    attestation_report_obj.get_response_message()
                    .get_opaque_data()
                    .get_data("OPAQUE_FIELD_ID_SWITCH_PDI")
                )
                switch_pdis = [0] * len(switch_pdis_in_evidence)
                for i in range(len(switch_pdis_in_evidence)):
                    switch_pdis[i] = read_field_as_little_endian(switch_pdis_in_evidence[i])

                switch_sids_set = set(switch_pdis)
                logger.debug(
                    "PPCIE: GPU Topology check: Unique switch sids found are %s",
                    switch_sids_set,
                )
                if len(switch_sids_set) != 4:
                    logger.error(
                        "PPCIE: GPU Topology check: Expected to have 4 unique switches in GPU attestation report but "
                        "found %d Topology check failed",
                        len(switch_sids_set),
                    )
                    status.topology_checks = False
                    sys.exit()

                # Ensuring we have the same unique switches for each of the GPU
                if len(self.unique_switches) == 0:
                    logger.debug(
                        "PPCIE: GPU Topology check: Setting unique switches %s",
                        self.unique_switches,
                    )
                    self.unique_switches = switch_sids_set
                elif self.unique_switches != switch_sids_set:
                    logger.error(
                        "PPCIE: GPU Topology check: We do not have unique switches connected to every GPU... Topology "
                        "check failed for Switches"
                    )
                    logger.debug(
                        "PPCIE: GPU Topology check: Unique switches expected to be %s "
                        "but found %s",
                        self.unique_switches,
                        switch_sids_set,
                    )
                    status.topology_checks = False
                    sys.exit()
        except Exception as e:
            status.topology_checks = False
            logger.error("PPCIE: Topology check failed for GPU due to exception: %s", e)
            sys.exit()
        logger.debug("PPCIE: GPU topology check completed")
        return status
