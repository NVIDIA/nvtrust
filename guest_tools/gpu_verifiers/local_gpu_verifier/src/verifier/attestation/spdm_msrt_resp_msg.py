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

from verifier.utils import read_field_as_little_endian
from verifier.exceptions import (
    NoMeasurementBlockError,
    MeasurementSpecificationError,
    ParsingError,
)


class DmtfMeasurement:
    """ The class to represent the DMTF Measurement.
    The structure of the Measurement when MeasurementSpecification field is bit 0 = DMTF in DMTF's SPDM 1.1 spec.
    OFFSET - FIELD                        - SIZE(in bytes)
    0      - DMTFSpecMeasurementValueType - 1
    1      - DMTFSpecMeasurementValueSize - 2
    3      - DMTFSpecMeasurementValue     - DMTFSpecMeasurementValueSize
    """
    FieldSize = {
        "DMTFSpecMeasurementValueType": 1,
        "DMTFSpecMeasurementValueSize": 2,
        "DMTFSpecMeasurementValue": None,
    }

    def get_measurement_value(self):
        """ Fetches the measurement value.

        Returns:
            [bytes]: the measurement value
        """
        return self.DMTFSpecMeasurementValue

    def get_measurement_value_type(self):
        """ Fetches the measurement value type.

        Returns:
            [int]: the measurement value type.
        """
        return self.DMTFSpecMeasurementValueType

    def get_measurement_value_size(self):
        """ Fetches the measurement value size in bytes.

        Returns:
            [int]: the size of measurement value in bytes.
        """
        return self.DMTFSpecMeasurementValueSize

    def set_measurement_value(self, value):
        """ Sets the measurement value field of the DMTF Measurement object.

        Args:
            value (bytes): the measurement value.
        """
        self.DMTFSpecMeasurementValue = value

    def set_measurement_value_type(self, value):
        """ Sets the measurement value type field of the DMTF Measurement object.

        Args:
            value (int): the measurement value type as an integer.
        """
        self.DMTFSpecMeasurementValueType = value

    def set_measurement_value_size(self, value):
        """ Sets the measurement values size field.

        Args:
            value (int): the measurement value size in bytes.
        """
        self.DMTFSpecMeasurementValueSize = value

    def parse(self, measurement_data):
        """ Parses the raw DMTF Measurement data and sets the various field values of the Measurement.

        Args:
            measurement_data (bytes): the raw DMTF Measurement data.
        """
        byte_index = 0

        x = measurement_data[byte_index: byte_index + self.FieldSize['DMTFSpecMeasurementValueType']]
        value = int(x.hex(), 16)
        self.set_measurement_value_type(value)
        byte_index = byte_index + self.FieldSize['DMTFSpecMeasurementValueType']

        x = measurement_data[byte_index: byte_index + self.FieldSize['DMTFSpecMeasurementValueSize']]
        value = int(read_field_as_little_endian(x), 16)
        self.set_measurement_value_size(value)
        byte_index = byte_index + self.FieldSize['DMTFSpecMeasurementValueSize']

        value = measurement_data[byte_index: byte_index + self.get_measurement_value_size()]
        self.set_measurement_value(value)
        byte_index = byte_index + self.get_measurement_value_size()

    def print_obj(self, logger):
        """ Prints all the fields of the object representing the DMTF Measurement.

        Args:
            logger (logging.Logger): the logger object.
        """
        logger.debug(f"DMTFSpecMeasurementValueType : {self.DMTFSpecMeasurementValueType}")
        logger.debug(f"DMTFSpecMeasurementValueSize : {self.DMTFSpecMeasurementValueSize}")
        logger.debug(f"DMTFSpecMeasurementValue     : {self.DMTFSpecMeasurementValue.hex()}")

    def __init__(self, measurement_data):
        """ The constructor method for the DmtfMeasurement class representing the DMTF Measurement.

        Args:
            measurement_data (bytes): the raw DMTF Measurement data.
        """
        assert type(measurement_data) is bytes

        self.DMTFSpecMeasurementValueType = None
        self.DMTFSpecMeasurementValueSize = None
        self.DMTFSpecMeasurementValue = None
        self.parse(measurement_data)


class MeasurementRecord:
    """ Class to represent the Measurement block.
    The structure of each of the Measurement block in DMTF's SPDM 1.1 spec is as follows:
    OFFSET - FIELD                    - SIZE(in bytes)
    0      - Index                    - 1
    1      - MeasurementSpecification - 1
    2      - MeasurementSize          - 2
    4      - Measurement              - MeasurementSize
    """
    FieldSize = {
        "Index": 1,
        "MeasurementSpecification": 1,
        "MeasurementSize": 2,
    }

    DMTF_MEASUREMENT_SPECIFICATION_VALUE = 1

    def get_measurements(self):
        """ Fetches all the measurement value and then returns them as a list.

        Returns:
            [list]: list of measurement values.
        """
        measurement_list = [None] * len(self.MeasurementBlocks)

        for index in self.MeasurementBlocks:
            measurement_list[index - 1] = self.MeasurementBlocks[index].get_measurement_value().hex()

        return measurement_list

    def parse(self, binary_data, settings):
        """ Parses the raw measurement record data and sets the fields of the class MeasurementRecord object
        representing the Measurement Record.

        Args:
            binary_data (bytes): the raw Measurement Record data
            settings (config.HopperSettings): the object containing the various config info.

        Raises:
            NoMeasurementBlockError: it is raised when there are zero number of measurement blocks.
            MeasurementSpecificationError: it is raised if any measurement block does not follow DMTF specification.
            ParsingError: it is raised if there is any issue in the parsing of the data.
        """
        assert type(binary_data) is bytes

        if self.NumberOfBlocks == 0:
            err_msg = "\tThere are no measurement blocks in the respone message."
            raise NoMeasurementBlockError(err_msg)

        byte_index = 0

        for _ in range(self.NumberOfBlocks):
            x = binary_data[byte_index: byte_index + self.FieldSize['Index']]
            index = int(x.hex(), 16)
            byte_index = byte_index + self.FieldSize['Index']

            x = binary_data[byte_index: byte_index + self.FieldSize['MeasurementSpecification']]
            measurement_specification = int(x.hex(), 16)
            if measurement_specification != self.DMTF_MEASUREMENT_SPECIFICATION_VALUE:
                raise MeasurementSpecificationError("Measurement block at index ", self.get_index(), \
                                                    " not following DMTF specification.\n\tQuitting now.")
            byte_index = byte_index + self.FieldSize['MeasurementSpecification']

            x = binary_data[byte_index: byte_index + self.FieldSize['MeasurementSize']]
            measurement_size = int(read_field_as_little_endian(x), 16)
            byte_index = byte_index + self.FieldSize['MeasurementSize']

            measurement_data = binary_data[byte_index: byte_index + measurement_size]
            self.MeasurementBlocks[index] = DmtfMeasurement(measurement_data)
            byte_index = byte_index + measurement_size

        if byte_index != len(binary_data):
            err_msg = "Something went wrong while parsing the MeasurementRecord.\nQuitting now."
            raise ParsingError(err_msg)

        count = 0
        for i in range(1, self.NumberOfBlocks + 1):

            if self.MeasurementBlocks[i] is not None \
               and len(self.MeasurementBlocks[i].get_measurement_value()) == self.MeasurementBlocks[i].get_measurement_value_size():
               count = count + 1

    def print_obj(self, logger):
        """ Prints all the field value of the class representing the Measurement Records.

        Args:
            logger (logging.Logger): the logger object.
        """

        for i in range(1, self.NumberOfBlocks + 1):
            logger.debug("----------------------------------------")
            logger.debug(f"Measurement Block index : {i}")
            self.MeasurementBlocks[i].print_obj(logger)

    def __init__(self, measurement_record_data, number_of_blocks, settings):
        """ The constructor method for the class MeasurementRecord to represent the measurement records.

        Args:
            measurement_record_data (bytes): the raw measurement record data
            number_of_blocks (int): the number of measurement blocks
            settings (config.HopperSettings): object that contains the config info.
        """
        assert type(measurement_record_data) is bytes
        assert type(number_of_blocks) is int

        self.MeasurementBlocks = dict()
        self.NumberOfBlocks = number_of_blocks
        self.parse(measurement_record_data, settings)


class OpaqueData:
    """ This is a class to represent the OpaqueData field in the SPDM GET_MEASUREMENT response message.
    The structure of the data in this field is as follows:
    [DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)][DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)]...
    """
    OPAQUE_DATA_TYPES = {
        1   : 'OPAQUE_FIELD_ID_CERT_ISSUER_NAME',
        2   : 'OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER',
        3   : 'OPAQUE_FIELD_ID_DRIVER_VERSION',
        4   : 'OPAQUE_FIELD_ID_GPU_INFO',
        5   : 'OPAQUE_FIELD_ID_SKU',
        6   : 'OPAQUE_FIELD_ID_VBIOS_VERSION',
        7   : 'OPAQUE_FIELD_ID_MANUFACTURER_ID',
        8   : 'OPAQUE_FIELD_ID_TAMPER_DETECTION',
        9   : 'OPAQUE_FIELD_ID_SMC',
        10  : 'OPAQUE_FIELD_ID_VPR',
        11  : 'OPAQUE_FIELD_ID_NVDEC0_STATUS',
        12  : 'OPAQUE_FIELD_ID_MSRSCNT',
        13  : 'OPAQUE_FIELD_ID_CPRINFO',
        14  : 'OPAQUE_FIELD_ID_BOARD_ID',
        15  : 'OPAQUE_FIELD_ID_CHIP_SKU',
        16  : 'OPAQUE_FIELD_ID_CHIP_SKU_MOD',
        17  : 'OPAQUE_FIELD_ID_PROJECT',
        18  : 'OPAQUE_FIELD_ID_PROJECT_SKU',
        19  : 'OPAQUE_FIELD_ID_PROJECT_SKU_MOD',
        20  : 'OPAQUE_FIELD_ID_FWID',
        21  : 'OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS',
        22  : 'OPAQUE_FIELD_ID_SWITCH_PDI',
        23  : 'OPAQUE_FIELD_ID_FLOORSWEPT_PORTS',
        24  : 'OPAQUE_FIELD_ID_POSITION_ID',
        25  : 'OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS',
        32  : 'OPAQUE_FIELD_ID_GPU_LINK_CONN',
        255 : 'OPAQUE_FIELD_ID_INVALID',
    }

    MSR_COUNT_SIZE = 4

    FieldSize = {
        "DataType"    : 2,
        "DataSize"    : 2,
        "PdiDataSize" : 8,
    }

    def get_data(self, field_name):
        """ Fetches the field value of the given field name.

        Args:
            field_name (str): the name/data type of the field in the opaque data.

        Returns:
            [bytes] : the content of the given field name.
        """
        assert type(field_name) is str

        if field_name == 'OPAQUE_FIELD_ID_FWID' and 'OPAQUE_FIELD_ID_FWID' not in self.OpaqueDataField:
            return b''

        return self.OpaqueDataField[field_name]

    def parse_measurement_count(self, data):
        """ Parses and creates a list of measurement count values from the OpaqueData field.

        Args:
            data (bytes): the raw measurement count data.

        Raises:
            ParsingError: it is raised if the length of the data is not a multiple of MSR_COUNT_SIZE.
        """

        if len(data) % self.MSR_COUNT_SIZE != 0:
            raise ParsingError("Invalid size of measurement count field data.")

        msr_cnt = list()
        number_of_elements = len(data) // self.MSR_COUNT_SIZE

        for i in range(number_of_elements):
            start = i * self.MSR_COUNT_SIZE
            end = start + self.MSR_COUNT_SIZE
            element = data[start: end]
            msr_cnt.append(int(read_field_as_little_endian(element), 16))

        self.OpaqueDataField['OPAQUE_FIELD_ID_MSRSCNT'] = msr_cnt

    def parse_switch_pdis(self, binary_data):
        """ Parses  the raw NvSwitch PDIs data of all the 18 NvLinks of the GPU.

        Args:
            binary_data (bytes): the raw NvSwitch PDI data.

        Raises:
            ParsingError: it is raised if the length off the data is not a multiple of self.FieldSize["PdiDataSize"]
        """
        if len(binary_data) % self.FieldSize['PdiDataSize'] != 0:
            raise ParsingError("Invalid size of switch PDI data.")

        byte_index = 0
        self.OpaqueDataField["OPAQUE_FIELD_ID_SWITCH_PDI"] = []

        while byte_index < len(binary_data):
            pdi = binary_data[byte_index : byte_index + self.FieldSize['PdiDataSize']]
            self.OpaqueDataField["OPAQUE_FIELD_ID_SWITCH_PDI"].append(pdi)
            byte_index = byte_index + self.FieldSize['PdiDataSize']

    def parse(self, binary_data):
        """ Parses the raw OpaqueData field of the SPDM GET_MEASUREMENT response message.

        Args:
            binary_data (bytes): the data content of the Opaque Data field.
        """
        byte_index = 0

        while byte_index < len(binary_data):

            x = binary_data[byte_index: byte_index + self.FieldSize['DataType']]
            value = int(read_field_as_little_endian(x), 16)
            data_type = self.OPAQUE_DATA_TYPES[value]
            byte_index = byte_index + self.FieldSize['DataType']

            x = binary_data[byte_index: byte_index + self.FieldSize['DataSize']]
            data_size = int(read_field_as_little_endian(x), 16)
            byte_index = byte_index + self.FieldSize['DataSize']

            value = binary_data[byte_index: byte_index + data_size]

            if data_type == 'OPAQUE_FIELD_ID_MSRSCNT':
                self.parse_measurement_count(value)
            elif data_type == 'OPAQUE_FIELD_ID_SWITCH_PDI':
                self.parse_switch_pdis(value)
            else:
                self.OpaqueDataField[data_type] = value

            byte_index = byte_index + data_size

    def print_obj(self, logger):
        """ Prints all the field content in the Opaque Data.

        Args:
            logger (logging.Logger): the logger object.
        """

        for field in self.OpaqueDataField:
            logger.debug(f"{field} : {self.OpaqueDataField[field]}")

    def __init__(self, binary_data):
        """ The constructor method for the class representing the OpaqueData.

        Args:
            binary_data (bytes): the Opaque data content.
        """
        assert type(binary_data) is bytes
        self.OpaqueDataField = dict()
        self.parse(binary_data)


class SpdmMeasurementResponseMessage:
    """ Class to represent the SPDM GET_MEASUREMENT response message.
    Following is the expected structure of the Successful MEASUREMENTS response message in DMTF's SPDM 1.1 spec.
    OFFSET   - FIELD                   - SIZE(in bytes)
    0        - SPDMVersion             - 1
    1        - RequestResponseCode     - 1
    2        - Param1                  - 1
    3        - Param2                  - 1
    4        - NumberOfBlocks          - 1
    5        - MeasurementRecordLength - 3
    8        - MeasurementRecord       - L1 = MeasurementRecordLength
    8+L1     - Nonce                   - 32
    40+L1    - OpaqueLength            - 2
    42+L1    - OpaqueData              - L2 = OpaqueLength
    42+L1+L2 - Signature               - 64
    """

    FieldSize = {
        "SPDMVersion": 1,
        "RequestResponseCode": 1,
        "Param1": 1,
        "Param2": 1,
        "NumberOfBlocks": 1,
        "MeasurementRecordLength": 3,
        "Nonce": 32,
        "OpaqueLength": 2,
    }

    def get_spdm_version(self):
        """ Fetches the SPDMVersion of the object representing the SPDM GET_MEASUREMENT response message.

        Returns:
            [bytes]: the SPDM version
        """
        return self.SPDMVersion

    def set_spdm_version(self, value):
        """ Sets the SPDMVersion field of the object representing the SPDM GET_MEASUREMENT response message.

        Args:
            value (bytes): the SPDM version
        """
        self.SPDMVersion = value

    def get_request_response_code(self):
        """ Fetches the RequestResponseCode field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [bytes]: the RequestResponse value.
        """
        return self.RequestResponseCode

    def set_request_response_code(self, value):
        """ Sets the RequestResponseCode field of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (bytes): the RequestResponse value.
        """
        self.RequestResponseCode = value

    def get_param1(self):
        """ Fetches the Param1 field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [bytes]: the Param1 value.
        """
        return self.Param1

    def set_param1(self, value):
        """ Sets the Param1 field of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (bytes): the Param1 value.
        """
        self.Param1 = value

    def get_param2(self):
        """ Fetches the Param2 field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [bytes]: the Param2 value
        """
        return self.Param2

    def set_param2(self, value):
        """ Sets the Param2 field of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (bytes): the Param2 value.
        """
        self.Param2 = value

    def get_number_of_blocks(self):
        """ Fetches the number of measurement blocks field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [int]: the Number of blocks.
        """
        return self.NumberOfBlocks

    def set_number_of_blocks(self, value):
        """ Sets the number of measurement blocks field of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (int): the number of blocks.
        """
        self.NumberOfBlocks = value

    def get_measurement_record_length(self):
        """ Fetches the length of the measurement record length field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [int]: the length of measurement record in bytes.
        """
        return self.MeasurementRecordLength

    def set_measurement_record_length(self, value):
        """ Sets the length of the measurement record length field of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (int): the length of measurement records in bytes.
        """
        self.MeasurementRecordLength = value

    def get_measurement_record(self):
        """ Fetches the MeasurementRecord object representing the measurement record of the SPDM GET_MEASUREMENT response.

        Returns:
            [MeasurementRecord]: the object representing the measurement record.
        """
        return self.MeasurementRecord

    def set_measurement_record(self, value):
        """ Assigns the MeasurementRecord object to the MeasurementRecord field of the SpdmMeasurementResponseMessage class.

        Args:
            value (MeasurementRecord): the MeasurementRecord class object.
        """
        self.MeasurementRecord = value

    def get_nonce(self):
        """ Fetches the Nonce field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [bytes]: the nonce value.
        """
        return self.Nonce

    def set_nonce(self, value):
        """ Sets the Nonce field value of the object representing the SPDM GET_MEASUREMENT response.

        Args:
            value (bytes): the nonce value.
        """
        self.Nonce = value

    def get_opaque_data_length(self):
        """ Fetches the length of OpaqueData field of the object representing the SPDM GET_MEASUREMENT response.

        Returns:
            [int]: the length of Opaque Data in bytes.
        """
        return self.OpaqueLength

    def set_opaque_data_length(self, value):
        """ Sets the length of opaque data field of the object representing the SPDM GET_MEASUREMENT response. 

        Args:
            value (int): the length of Opaque data in bytes.
        """
        self.OpaqueLength = value

    def get_opaque_data(self):
        """ Fetches the OpaqueData class object representing the Opaque data in the SPDM GET_MEASUREMENT response.

        Returns:
            [OpaqueData]: object of class OpaqueData.
        """
        return self.OpaqueData

    def get_signature(self):
        """ Fetches the signature field content of the SpdmMeasurementResponseMessage class object.

        Returns:
            [bytes]: the signature value.
        """
        return self.Signature

    def set_signature(self, value):
        """ Assigns the signature field value of the SpdmMeasurementResponseMessage class object.

        Args:
            value (bytes): the signature value.
        """
        self.Signature = value

    def parse(self, response, settings):
        """ Parses the raw SPDM GET_MEASUREMENT response message and sets the various fields of the SpdmMeasurementResponseMessage class object.

        Args:
            response (bytes): the raw data content of the SPDM GET_MEASUREMENT response message.
            settings (config.HopperSettings): object that contains the config info.
        """
        assert type(response) is bytes

        byte_index = 0

        value = response[byte_index: byte_index + self.FieldSize['SPDMVersion']]
        self.set_spdm_version(value)
        byte_index = byte_index + self.FieldSize['SPDMVersion']

        value = response[byte_index: byte_index + self.FieldSize['RequestResponseCode']]
        self.set_request_response_code(value)
        byte_index = byte_index + self.FieldSize['RequestResponseCode']

        value = response[byte_index: byte_index + self.FieldSize['Param1']]
        self.set_param1(value)
        byte_index = byte_index + self.FieldSize['Param1']

        value = response[byte_index: byte_index + self.FieldSize['Param2']]
        self.set_param2(value)
        byte_index = byte_index + self.FieldSize['Param2']

        x = response[byte_index: byte_index + self.FieldSize['NumberOfBlocks']]
        value = int(x.hex(), 16)
        self.set_number_of_blocks(value)
        byte_index = byte_index + self.FieldSize['NumberOfBlocks']

        x = response[byte_index: byte_index + self.FieldSize['MeasurementRecordLength']]
        value = int(read_field_as_little_endian(x), 16)
        self.set_measurement_record_length(value)
        byte_index = byte_index + self.FieldSize['MeasurementRecordLength']

        measurement_record = response[byte_index: byte_index + self.get_measurement_record_length()]
        self.set_measurement_record(MeasurementRecord(measurement_record, self.get_number_of_blocks(), settings))
        byte_index = byte_index + self.get_measurement_record_length()

        value = response[byte_index: byte_index + self.FieldSize['Nonce']]
        self.set_nonce(value)
        byte_index = byte_index + self.FieldSize['Nonce']

        x = response[byte_index: byte_index + self.FieldSize['OpaqueLength']]
        x = read_field_as_little_endian(x)
        value = int(x, 16)
        self.set_opaque_data_length(value)
        byte_index = byte_index + self.FieldSize['OpaqueLength']

        opaque_data_content = response[byte_index: byte_index + self.get_opaque_data_length()]
        self.OpaqueData = OpaqueData(opaque_data_content)
        byte_index = byte_index + self.get_opaque_data_length()

        value = response[byte_index: byte_index + self.FieldSize['Signature']]
        self.set_signature(value)
        byte_index = byte_index + self.FieldSize['Signature']

    def print_obj(self, logger):
        """ Prints all the fields of the class SpdmMeasurementResponseMessage representing the SPDM GET_MEASUREMENT response message.

        Args:
            logger (logging.Logger): the logger object.
        """
        logger.debug("GET MEASUREMENT RESPONSE MESSAGE")
        logger.debug(f"SPDMVersion : {self.SPDMVersion.hex()}")
        logger.debug(f"RequestResponseCode : {self.RequestResponseCode.hex()}")
        logger.debug(f"Param1 : {self.Param1.hex()}")
        logger.debug(f"Param2 : {self.Param2.hex()}")
        logger.debug(f"NumberOfBlocks : {self.NumberOfBlocks}")
        logger.debug(f"MeasurementRecordLength : {self.MeasurementRecordLength}")
        logger.debug(f"MeasurementRecord :")
        self.MeasurementRecord.print_obj(logger)
        logger.debug(f"Nonce : {self.Nonce.hex()}")
        logger.debug(f"OpaqueLength : {self.OpaqueLength}")
        logger.debug(f"OpaqueData :")
        self.OpaqueData.print_obj(logger)
        logger.debug(f"Signature : {self.Signature.hex()}")

    def __init__(self, response, settings):
        """ The constructor method for the class SpdmMeasurementResponseMessage representing the SPDM GET_MEASUREMENT response message.

        Args:
            response (bytes): The raw SPDM GET_MEASUREMENT response message.
            settings (config.HopperSettings): the object containing various config.

        Raises:
            ParsingError: _description_
        """
        assert type(response) is bytes
        self.SPDMVersion = None
        self.RequestResponseCode = None
        self.Param1 = None
        self.Param2 = None
        self.NumberOfBlocks = None
        self.MeasurementRecordLength = None
        self.MeasurementRecord = None
        self.Nonce = None
        self.OpaqueLength = None
        self.OpaqueData = None
        self.Signature = None
        self.FieldSize['Signature'] = settings.signature_length
        try:
            self.parse(response, settings)
        except Exception as error:
            raise ParsingError("Could not parse the GET MEASUREMENT response message.")
