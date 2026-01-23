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

from ecdsa import (
    VerifyingKey,
    BadSignatureError,
)

from ..utils import extract_public_key
from ..utils.logging import get_logger

from .spdm_msrt_resp_msg import SpdmMeasurementResponseMessage
from .spdm_msrt_req_msg import SpdmMeasurementRequestMessage

from ..exceptions.exception import (
    NoMeasurementsError,
    ParsingError,
)

logger = get_logger()

class AttestationReport:
    """ A class to represent the attestation report coming from the GPU driver.

    The class to encapsulate the Attestation report which comprises of the
    SPDM GET MEASUREMENT request message and the SPDM GET MEASUREMENT response
    message.
    """

    LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE = 37

    def extract_response_message(self, attestation_report_data):
        """ Extracts the SPDM GET_MEASUREMENT response message from the attestation report.

        Args:
            attestation_report_data (bytes): the attestation report coming from gpu via the nvml api.

        Returns:
            [bytes]: returns the extracted SPDM GET_MEASUREMENT response message.
        """
        assert type(attestation_report_data) is bytes
        assert len(attestation_report_data) > self.LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE

        response = attestation_report_data[self.LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE : ]
        return response

    def extract_request_message(self, attestation_report_data):
        """ Extracts the SPDM GET_MEASUREMENT request message from the attestation report.

        Args:
            attestation_report_data (bytes): the attestation report coming from gpu via the nvml api.

        Returns:
            [bytes]: returns the extracted SPDM GET_MEASUREMENT request message.
        """
        assert type(attestation_report_data) is bytes
        assert len(attestation_report_data) > self.LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE

        request = attestation_report_data[ : self.LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE]
        return request

    @staticmethod
    def concatenate(request_data, response_data, signature_length):
        """ Computes the binary data over which the signature verification is to be done.
        
        Args:
        request_data (bytes) : the SPDM GET_MEASUREMENTS request message.
        response_data (bytes) : the successful SPDM GET_MEASUREMENT response message.
        signature_length (int): the size of the digital signature in number of bytes.

        Returns:
            [bytes]: returns the binary data whose signature verification is to be done.
        """
        assert type(request_data) is bytes
        assert type(response_data) is bytes
        assert type(signature_length) is int

        if not len(response_data) > signature_length:
            raise ParsingError("The the length of the SPDM GET_MEASUREMENT response message is less than \
                               or equal to the length of the signature field, which is not correct.")

        data = request_data + response_data
        data = data[ : len(data) - signature_length]
        return data

    def verify_signature(self, certificate, signature_length, hashfunc):
        """ Performs the signature verification of the attestation report.

        Args:
            certificate (OpenSSL.crypto.X509): The GPU attestation leaf certificate.
            signature_length (int): the length of the signature field of the attestation report.
            hashfunc (_hashlib.HASH): The hashlib hash function.

        Returns:
            [bool]: return True if the signature verification is successful 
            otherwise, return False.
        """
        try:
            logger.debug("Extracting the public key from the certificate for the attestation report.")
            public_key = extract_public_key(certificate)
            verifying_key = VerifyingKey.from_pem(public_key)
            logger.debug("Extracted the public key from the certificate for the the attestation report.")

            data_whose_signature_is_to_be_verified = AttestationReport.concatenate(request_data = self.request_data,
                                                                                   response_data = self.response_data,
                                                                                   signature_length = signature_length)
            signature = self.get_response_message().get_signature()
            
            logger.debug("Verifying the signature of the attestation report.")
            status = verifying_key.verify(signature, data_whose_signature_is_to_be_verified, hashfunc = hashfunc)
            return status
        except BadSignatureError:
            return False

        except Exception as error:
            err_msg = "Something went wrong during attestation report signature verification."
            logger.info(err_msg)
            return False

    def get_measurements(self):
        """ Fetches the runtime measurements from the attestation report.

        Raises:
            NoMeasurementsError: It is raised in case there are no or blank measurement block.

        Returns:
            [list]: list of measurement values.
        """
        measurement_list = self.response_message.get_measurement_record().get_measurements()
        logger.debug("Runtime measurements are : \n\t\t\t\t\t\t\t{}".format('\n\t\t\t\t\t\t\t'.join(map(str, measurement_list))))

        if len(measurement_list) == 0:
            err_msg = "\tNo GPU runtime measurements found."
            logger.error(err_msg)
            raise NoMeasurementsError(err_msg + "\n\tQuitting now.")
        
        return measurement_list

    def get_request_message(self):
        """ Fetches the SPDM GET MEASUREMENT request message represented as an object of class SpdmMeasurementRequestMessage.

        Returns:
            [SpdmMeasurementRequestMessage]: the object representing the SPDM GET MEASUREMENT request message.
        """
        return self.request_message
    
    def get_response_message(self):
        """ Fetches the SPDM GET MEASUREMENT response message represented as an object of class SpdmMeasurementResponseMessage.

        Returns:
            [SpdmMeasurementResponseMessage]: the object representing the SPDM GET MEASUREMENT response message.
        """
        return self.response_message

    def print_obj(self, logger):
        """ Prints all the fields of the request and response message in the attestation report object.

        Args:
            logger (logging.Logger): the logger object which prints the output according to its set level.
        """
        self.request_message.print_obj(logger)
        self.response_message.print_obj(logger)

    def __init__(self, data, settings):
        """ The constructor for the attestation report class. 

        Args:
            data (bytes): the raw attestation report data coming from the nvml api.
            settings (config.HopperSettings): the setting object that have the various config info.
        """
        assert type(data) is bytes

        self.request_data = self.extract_request_message(data)
        self.response_data = self.extract_response_message(data)
        self.request_message = SpdmMeasurementRequestMessage(self.request_data)
        self.response_message = SpdmMeasurementResponseMessage(self.response_data, settings)
