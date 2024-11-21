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

from .config import (
    BaseSettings,
)
import logging
from .exceptions import InvalidMeasurementIndexError
from nv_attestation_sdk.utils.logging_config import get_logger
logger = get_logger()


class SwitchVerifier:
    """ A class to match the runtime Switch measurements against the golden
    measurements.
    """

    def verify(self, settings):
        """ This methods compares the runtime measurement with the golden measurement in order to check if there is any discrepancy.

        Args:
            settings (config.LS10Settings): the object containing the various config info.

        Returns:
            [bool]: returns True if all the valid golden measurements values matches with the
            corresponding runtime measurements. Otherwise, returns False.
        """
        logger.info("\tComparing measurements (runtime vs golden)")

        if len(self.runtime_measurements) == 0:
            logger.warning("\t\t\tWarning : no measurements from attestation report received.")

        if len(self.golden_measurements) == 0:
            logger.warning("\t\t\tWarning : no golden measurements from RIMs received.")

        # Make sure that active golden measurement are always less than or equal to run time measurement
        if len(self.golden_measurements) > len(self.runtime_measurements):
            logger.warning(
                "\t\t\tWarning : Golden measurement are more than measurements in Attestation report.")
            return False

        list_of_mismatched_indexes = list()

        for i in self.golden_measurements:

            is_matching = False

            for j in range(self.golden_measurements[i].get_number_of_alternatives()):

                if self.golden_measurements[i].get_value_at_index(j) == self.runtime_measurements[i] and \
                        self.golden_measurements[i].get_size() == len(self.runtime_measurements[i]) // 2:
                    is_matching = True

            if not is_matching:
                # Measurements are not matching.
                list_of_mismatched_indexes.append(i)

        if len(list_of_mismatched_indexes) > 0:

            logger.info("""\t\t\tThe runtime measurements are not matching with the
                        golden measurements at the following indexes(starting from 0) :\n\t\t\t[""")

            list_of_mismatched_indexes.sort()

            for i, index in enumerate(list_of_mismatched_indexes):
                if i != len(list_of_mismatched_indexes) - 1:
                    logger.info(f'\t\t\t{index}, ')
                else:
                    logger.info("\t\t\t" + str(index))
            logger.info("\t\t\t]")

            return False
        else:
            logger.info("\t\t\tThe runtime measurements are matching with the golden measurements.\
                            \n\t\tSwitch is in expected state.")
            settings.mark_measurements_as_matching()
            return True

    def generate_golden_measurement_list(self, vbios_golden_measurements, settings):
        """ This method takes the driver and vbios golden measurements and
        combines them into a single dictionary with the measurement index as
        the key and the golden measurement object as the value.

        Args:
            vbios_golden_measurements (dict): the dictionary containing the vbios golden measurements.
            settings (config.LS10Settings): the object containing the various config info.

        Raises:
            InvalidMeasurementIndexError: it is raised in case both the driver and vbios RIM file have
                                          active measurement at the same index.
        """
        self.golden_measurements = dict()

        for gld_msr_idx in vbios_golden_measurements:

            if vbios_golden_measurements[gld_msr_idx].is_active() and \
                    gld_msr_idx in self.golden_measurements:
                raise InvalidMeasurementIndexError(
                    f"The driver and vbios RIM have measurement at the same index : {gld_msr_idx}")

            elif vbios_golden_measurements[gld_msr_idx].is_active():
                self.golden_measurements[gld_msr_idx] = vbios_golden_measurements[gld_msr_idx]

        settings.mark_no_driver_vbios_measurement_index_conflict()

    def __init__(self, attestation_report_obj, vbios_rim_obj, settings):
        """ The constructor method for the Verifier class.

        Args:
            attestation_report_obj (AttestationReport): the attestation report.
            vbios_rim_obj (rim.RIM): the vbios RIM object containing the vbios golden measurement.
            settings (config.LS10Settings): the object containing the various config info.
        """
        self.generate_golden_measurement_list(vbios_rim_obj.get_measurements(),
                                              settings)
        self.runtime_measurements = attestation_report_obj.get_measurements()
