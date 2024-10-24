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

import logging

from ..exceptions import ParsingError

class SpdmMeasurementRequestMessage:
    """ Class representing the SPDM GET_MEASUREMENT request message.
    Following is the expected structure of the MEASUREMENTS request message in DMTF's SPDM 1.1 spec.
    OFFSET   - FIELD                   - SIZE(in bytes)
    0        - SPDMVersion             - 1
    1        - RequestResponseCode     - 1
    2        - Param1                  - 1
    3        - Param2                  - 1
    4        - Nonce                   - 32
    36       - SlotIDParam             - 1
    """
    FieldSize = {
        "SPDMVersion"         : 1,
        "RequestResponseCode" : 1,
        "Param1"              : 1,
        "Param2"              : 1,
        "Nonce"               : 32,
        "SlotIDParam"         : 1,
    }

    def get_spdm_version(self):
        """ Fetches the spdm version field of the object of SpdmMeasurementRequestMessage.

        Returns:
            [bytes]: the spdm version.
        """
        return self.SPDMVersion
    
    def set_spdm_version(self, value):
        """ Sets the spdm version field of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the spdm version.
        """
        self.SPDMVersion = value

    def get_request_response_code(self):
        """ Fetches the RequestResponseCode field of the object representing the SPDM GET_MEASUREMENT request.

        Returns:
            [bytes]: the RequestResponseCode
        """
        return self.RequestResponseCode
    
    def set_request_response_code(self, value):
        """ Sets the RequestResponseCode field of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the RequestResponse value.
        """
        self.RequestResponseCode = value

    def get_param1(self):
        """ Fetches the Param1 field of the object representing the SPDM GET_MEASUREMENT request.

        Returns:
            [bytes]: the Param1 value.
        """
        return self.Param1
    
    def set_param1(self, value):
        """ Sets the Param1 field of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the Param1 value.
        """
        self.Param1 = value

    def get_param2(self):
        """ Fetches the Param2 field of the object representing the SPDM GET_MEASUREMENT request.

        Returns:
            [bytes]: the Param2 value
        """
        return self.Param2

    def set_param2(self, value):
        """ Sets the Param2 field of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the Param2 value.
        """
        self.Param2 = value

    def get_nonce(self):
        """ Fetches the Nonce field of the object representing the SPDM GET_MEASUREMENT request.

        Returns:
            [bytes]: the nonce value.
        """
        return self.Nonce
    
    def set_nonce(self, value):
        """ Sets the Nonce field value of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the nonce value.
        """
        self.Nonce = value

    def get_slot_id_param(self):
        """ Fetches the SlotIDParam field value of the object representing the SPDM GET_MEASUREMENT request.

        Returns:
            [bytes]: SlotIDParam value.
        """
        return self.SlotIDParam

    def set_slot_id_param(self, value):
        """ Sets the SlotIDParam field value of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            value (bytes): the SlotIDParam value.
        """
        self.SlotIDParam = value

    def parse(self, request_data):
        """ Parses the raw SPDM GET_MEASUREMENT request message.

        Args:
            request_data (bytes): the raw message data.

        Raises:
            ParsingError: it is raised if there is any incorrect data field length.
        """
        byte_index = 0

        value = request_data[byte_index : byte_index + self.FieldSize['SPDMVersion']]
        self.set_spdm_version(value)
        byte_index = byte_index + self.FieldSize['SPDMVersion']

        value = request_data[byte_index : byte_index + self.FieldSize['RequestResponseCode']]
        self.set_request_response_code(value)
        byte_index = byte_index + self.FieldSize['RequestResponseCode']

        value = request_data[byte_index : byte_index + self.FieldSize['Param1']]
        self.set_param1(value)
        byte_index = byte_index + self.FieldSize['Param1']

        value = request_data[byte_index : byte_index + self.FieldSize['Param2']]
        self.set_param2(value)
        byte_index = byte_index + self.FieldSize['Param2']

        value = request_data[byte_index : byte_index + self.FieldSize['Nonce']]
        self.set_nonce(value)
        byte_index = byte_index + self.FieldSize['Nonce']

        value = request_data[byte_index : byte_index + self.FieldSize['SlotIDParam']]
        self.set_slot_id_param(value)
        byte_index = byte_index + self.FieldSize['SlotIDParam']

        if byte_index != len(request_data):
            err_msg = "Something went wrong during parsing the SPDM GET MEASUREMENT request message."
            self.info_log.error(err_msg)
            raise ParsingError(err_msg)

    def print_obj(self, logger):
        """ Prints all the field values of the object representing the SPDM GET_MEASUREMENT request.

        Args:
            logger (logging.Logger): the logger object.
        """
        logger.debug("GET MEASUREMENT REQUEST MESSAGE")
        logger.debug(f"SPDMVersion         : {self.SPDMVersion.hex()}")
        logger.debug(f"RequestResponseCode : {self.RequestResponseCode.hex()}")
        logger.debug(f"Param1              : {self.Param1.hex()}")
        logger.debug(f"Param2              : {self.Param2.hex()}")
        logger.debug(f"Nonce               : {self.Nonce.hex()}")
        logger.debug(f"SlotIDParam         : {self.SlotIDParam.hex()}")

    def __init__(self, request_data, info_log):
        """ The constructor method for the SpdmMeasurementRequestMessage class representing the SPDM GET_MEASUREMENT
        request message.

        Args:
            request_data (bytes): raw SPDM GET_MEASUREMENT request message.
            info_logger (logging.Logger) : the logger object which prints to the output to the terminal.
        """
        assert type(request_data) is bytes
        assert type(info_log) is logging.Logger

        self.info_log = info_log
        self.SPDMVersion = None
        self.RequestResponseCode = None
        self.Param1 = None
        self.Param2 = None
        self.Nonce  = None
        self.SlotIDParam = None
        self.parse(request_data)
