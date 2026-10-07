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

"""Validate GPU and NVSwitch topology from attested SDK claims."""

import sys

from ..utils.logging import get_logger

logger = get_logger()

GPU_SWITCH_PDIS_CLAIM = "x-nvidia-gpu-switch-pdis"
SWITCH_PDI_CLAIM = "x-nvidia-switch-pdi"
SWITCH_GPU_PDIS_CLAIM = "x-nvidia-switch-gpu-pdis"
DISABLED_PDI = "0000000000000000"
EXPECTED_GPU_COUNT = 8
EXPECTED_SWITCH_COUNT = 4


def _pdi_set(claims, claim_name):
    """Return a canonical PDI set from one device's claims."""
    if not isinstance(claims, dict):
        raise ValueError("device claims must be an object")
    pdis = claims.get(claim_name)
    if not isinstance(pdis, list) or any(not isinstance(pdi, str) for pdi in pdis):
        raise ValueError(f"{claim_name} must be an array of strings")
    return {pdi.upper() for pdi in pdis}


def _pdi(claims, claim_name):
    """Return one canonical PDI from a device's claims."""
    if not isinstance(claims, dict):
        raise ValueError("device claims must be an object")
    pdi = claims.get(claim_name)
    if not isinstance(pdi, str):
        raise ValueError(f"{claim_name} must be a string")
    return pdi.upper()


class TopologyValidation:
    """Validate connectivity reported by GPU and NVSwitch claims."""

    def __init__(self):
        self.opaque_data_field = {}
        self.unique_switches = set()
        self.unique_gpus = set()

    @staticmethod
    def _fail(status, message, *args):
        logger.error(message, *args)
        status.topology_checks = False
        sys.exit()

    def switch_topology_check(self, switch_claims_list, number_of_gpus, status):
        """Validate the GPU topology reported by every NVSwitch."""
        logger.debug("Performing NVSwitch topology check")
        if len(switch_claims_list) != EXPECTED_SWITCH_COUNT:
            self._fail(
                status,
                "NVSwitch topology check failed: expected %d claim objects but found %d",
                EXPECTED_SWITCH_COUNT,
                len(switch_claims_list),
            )

        switch_pdis = set()
        for claims in switch_claims_list:
            try:
                switch_pdi = _pdi(claims, SWITCH_PDI_CLAIM)
                gpu_pdis = _pdi_set(claims, SWITCH_GPU_PDIS_CLAIM)
            except ValueError as error:
                self._fail(
                    status,
                    "NVSwitch topology check failed: %s",
                    error,
                )


            if len(gpu_pdis) != number_of_gpus:
                self._fail(
                    status,
                    "NVSwitch topology check failed: expected each NVSwitch claim "
                    "to report %d unique GPU PDIs but found %d",
                    number_of_gpus,
                    len(gpu_pdis),
                )

            self.unique_gpus.update(gpu_pdis)
            switch_pdis.add(switch_pdi)

        if len(self.unique_gpus) != number_of_gpus:
            self._fail(
                status,
                "NVSwitch topology check failed: expected %d unique GPU PDIs "
                "across NVSwitch claims but found %d",
                number_of_gpus,
                len(self.unique_gpus),
            )
        if len(switch_pdis) != EXPECTED_SWITCH_COUNT:
            self._fail(
                status,
                "NVSwitch topology check failed: expected %d unique NVSwitch PDIs but found %d",
                EXPECTED_SWITCH_COUNT,
                len(switch_pdis),
            )

        unknown_switches = self.unique_switches - switch_pdis
        if unknown_switches:
            self._fail(
                status,
                "NVSwitch topology check failed: GPU-reported NVSwitch PDIs %s are not "
                "present in NVSwitch claims",
                unknown_switches,
            )

        status.topology_checks = True
        logger.debug("NVSwitch topology check completed")
        return status

    def gpu_topology_check(self, gpu_claims_list, number_of_switches, status):
        """Validate the NVSwitch topology reported by every GPU."""
        logger.debug("Performing GPU topology check")
        if len(gpu_claims_list) != EXPECTED_GPU_COUNT:
            self._fail(
                status,
                "GPU topology check failed: expected %d claim objects but found %d",
                EXPECTED_GPU_COUNT,
                len(gpu_claims_list),
            )

        for claims in gpu_claims_list:
            try:
                switch_pdis = _pdi_set(claims, GPU_SWITCH_PDIS_CLAIM)
            except ValueError as error:
                self._fail(
                    status,
                    "GPU topology check failed: %s",
                    error,
                )

            switch_pdis.discard(DISABLED_PDI)
            if len(switch_pdis) != number_of_switches:
                self._fail(
                    status,
                    "GPU topology check failed: expected each GPU claim to report "
                    "%d unique NVSwitch PDIs but found %d",
                    number_of_switches,
                    len(switch_pdis),
                )

            self.unique_switches.update(switch_pdis)

        if len(self.unique_switches) != number_of_switches:
            self._fail(
                status,
                "GPU topology check failed: expected %d unique NVSwitch PDIs "
                "across GPU claims but found %d",
                number_of_switches,
                len(self.unique_switches),
            )
        logger.debug("GPU topology check completed")
        return status
