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

import os
import io
import sys

from signxml import XMLVerifier
from signxml.exceptions import InvalidSignature
from lxml import etree
from OpenSSL import crypto

from .golden_measurement import GoldenMeasurement
from verifier.config import (
    BaseSettings,
    event_log,
    info_log,
    __author__,
    __copyright__,
    __version__,
)
from verifier.cc_admin_utils import CcAdminUtils
from verifier.exceptions import (
    ElementNotFoundError,
    EmptyElementError,
    InvalidCertificateError,
    NoRIMMeasurementsError,
    RIMSchemaValidationError,
    RIMFetchError,
    RIMSignatureVerificationError,
    InvalidMeasurementIndexError,
    InvalidRIMNameError,
    RIMCertChainVerificationError,
    RIMCertChainOCSPVerificationError,
)

class RIM:
    """ A class to process and manage all the processing of the RIM files.
    RIM module Trusted Computing Group Reference Integrity Manifest of the 
    Verifier is used to perform the authentication and access of the golden
    measurements.
    """

    @staticmethod
    def get_element(parent_element, name_of_element):
        """ A static method that gives the child element of the parent_element with the given name.

        Args:
            parent_element (lxml.etree._Element): the parent of the required element.
            name_of_element (str): the name of the required element.

        Returns:
            [lxml.etree._Element]: the required element.
        """
        assert isinstance(parent_element, etree._Element)
        assert type(name_of_element) is str
        
        for child in parent_element.getchildren():

            if (child.tag).find(name_of_element) != -1:
                return child
        
        return None

    @staticmethod
    def get_all_elements(parent_element, name_of_element):
        assert isinstance(parent_element, etree._Element)
        assert type(name_of_element) is str
        
        list_of_elements = list()
        for child in parent_element.getchildren():

            if (child.tag).find(name_of_element) != -1:
                list_of_elements.append(child)
        return list_of_elements

    @staticmethod
    def read(base_RIM_path = None, content = None):
        """ Static method that reads the signed base RIM from the disk.
        
        Argument:
        base_RIM_path (str) : the path to the signed base RIM.
        content (str) : the content of the RIM file as a string.
        Returns:
        root (lxml.etree._Element) : the root element of the base RIM.
        """
        if base_RIM_path is not None and content is None:
            try:
                assert type(base_RIM_path) is str
        
                with open(base_RIM_path, 'rb') as f:
                    read_data = f.read()

            except OSError:
                event_log.error(f'Unable to read {base_RIM_path} \nPlease provide a valid RIM file.')
                raise RIMFetchError(f'Unable to read {base_RIM_path} \nPlease provide a valid RIM file.')

            file_stream = io.BytesIO(read_data)

        elif base_RIM_path is None and content is not None:
            file_stream = io.StringIO(content)

        else:
            raise RIMFetchError("Invalid parameters!!")

        parser = etree.XMLParser(resolve_entities=False)
        new_swidtag_tree = etree.parse(file_stream, parser) 
        new_root = new_swidtag_tree.getroot()
        return new_root
    
    def validate_schema(self, schema_path):
        """ Performs the schema validation of the base RIM against a given schema.

        Args:
            schema_path (str): the path to the swidtag schema xsd file.

        Returns:
            [bool]: Ture if the schema validation is successful otherwise, returns False.
        """
        try:
            parser = etree.XMLParser(resolve_entities=False)
            xml_schema_document = etree.parse(schema_path, parser)

            xml_schema = etree.XMLSchema(xml_schema_document)

            result = xml_schema.validate(self.root)
        except Exception:
            err_msg = "\t\tRIM Schema validation failed."
            event_log.error(err_msg)
            
            raise RIMSchemaValidationError(err_msg)

        return result
    
    def get_colloquial_version(self):
        """ Parses RIM to return the driver/vbios version which is present in the RIM as
        colloquial version.

        Raises:
            ElementNotFoundError: Raises exception if the Meta element is not present.
            EmptyElementError: Raises exception if the colloquialVersion field is empty.

        Returns:
            [str]: The colloquialVersion attribute of Meta element.
        """
        Meta = RIM.get_element(self.root, "Meta")
        if Meta is None:
            err_msg = "\t\tNo Meta element found in the RIM."
            info_log.error(err_msg)
            raise ElementNotFoundError(err_msg)
        
        version = Meta.attrib['colloquialVersion']

        if version is None or version == '':
            err_msg = "Driver version not found in the RIM."
            info_log.error(err_msg)
            raise EmptyElementError(err_msg)
        
        event_log.debug(f'The driver version in the RIM file is {version}')
        version = version.lower()
        return version

    def extract_certificates(self):
        """ Extracts all the x509 certificate in PEM format from the base RIM.

        Raises:
            ElementNotFoundError: it is raised if the required element is not present.
            InvalidCertificateError: it is raised if there is any problem in
                                    extracting the X509 certificate from the RIM file.

        Returns:
            [bytes]: the X509 PEM certificate data.
        """
        try:
            Signature = RIM.get_element(self.root, "Signature")

            if Signature is None:
                err_msg = "No Signature found in the RIM."
                info_log.error(err_msg)
                raise ElementNotFoundError(err_msg)

            KeyInfo = RIM.get_element(Signature, "KeyInfo")
            if KeyInfo is None:
                err_msg = "No KeyInfor found in the RIM."
                info_log.error(err_msg)
                raise ElementNotFoundError(err_msg)

            X509Data = RIM.get_element(KeyInfo, "X509Data")
            if X509Data is None:
                err_msg = "X509Data not found in the RIM."
                info_log.error(err_msg)
                raise ElementNotFoundError(err_msg)

            X509Certificates = RIM.get_all_elements(X509Data, "X509Certificate")

            if len(X509Certificates) == 0:
                err_msg = "X509Certificates not found in the RIM."
                info_log.error(err_msg)
                raise ElementNotFoundError(err_msg)
            
            result = list()
            for i in range(len(X509Certificates) - 1):
                header = "-----BEGIN CERTIFICATE-----\n"
                cert_string = X509Certificates[i].text
                cert_string = cert_string.replace(' ','')
                tail = "-----END CERTIFICATE-----\n"
                final = header + cert_string + tail
                cert_bytes = final.encode()
                x509_cert_object = crypto.load_certificate(type=crypto.FILETYPE_PEM, buffer=cert_bytes)

                if not isinstance(x509_cert_object, crypto.X509):
                    raise ValueError()
                result.append(x509_cert_object)

        except Exception as error:
            info_log.error(error)
            err_msg = "\t\tThere was a problem while extracting the X509 certificate from the RIM."
            info_log.info(err_msg)
            raise InvalidCertificateError(err_msg)

        return result
    
    def verify_signature(self, settings):
        """ Verifies the signature of the base RIM.
        
        Arguments:
        settings (config.HopperSettings): the object containing the various config info.
        
        Returns: 
            [bool] : If signature verification is successful, then return the True. Otherwise,
                raises RIMSignatureVerificationError.
        """
        if self.rim_name == 'driver':
            event_log.info("Driver rim cert has been extracted successfully")
        else:
            event_log.info("Vbios rim cert has been extracted successfully")
        try:
            # performs the signature verification of the RIM. We will get the root of the RIM
            # if the signature verification is successful otherwise, it raises InvalidSignature exception.
            verified_root = XMLVerifier().verify(self.root, ca_pem_file = settings.RIM_ROOT_CERT, ca_path = settings.ROOT_CERT_DIR).signed_xml

            if verified_root is None:
                err_msg = "\t\t\tRIM signature verification failed."
                event_log.error(err_msg)
                raise RIMSignatureVerificationError(err_msg)

        except InvalidSignature as error:
            err_msg = "\t\t\tRIM signature verification failed."
            event_log.error(err_msg)
            raise RIMSignatureVerificationError(err_msg)
        
        except Exception as error:
            info_log.error(error)
            err_msg = "\t\t\tRIM signature verification failed."
            event_log.error(err_msg)
            raise RIMSignatureVerificationError(err_msg)

        info_log.info(f"\t\t\t{self.rim_name} RIM signature verification successful.")
        self.root = verified_root
        if self.rim_name == 'driver':
            settings.mark_driver_rim_cert_validated_successfully()
        else:
            settings.mark_vbios_rim_cert_validated_successfully()
        return True
    
    def get_measurements(self):
        """ Returns the dictionary object that contains the golden measurement.

        Returns:
            [dict]: the dictionary containing the golden measurement.
        """
        return self.measurements_obj

    def parse_measurements(self, settings):
        """ Lists the measurements of the Resource tags in the base RIM.

        Args:
            settings (config.HopperSettings): the object containing the various config info.

        Raises:
            ElementNotFoundError: it is raised if a required element is not found.
            InvalidMeasurementIndexError: it is raised in case multiple measurement are assigned same index.
            NoRIMMeasurementsError: it is raised in case there are no golden measurements in the RIM file.
        """       
        self.measurements_obj = dict()
        Payload = RIM.get_element(self.root, "Payload")

        if Payload is None:
            err_msg = "Payload not found in the RIM."
            info_log.error(err_msg)
            raise ElementNotFoundError(err_msg)

        for child in Payload:

            if child.attrib['active'] == 'False':
                active = False
            else:
                active =True

            index = int(child.attrib['index'])
            alternatives = int(child.attrib['alternatives'])
            measurements_values = list()
            
            for i in range(alternatives):
                measurements_values.append(child.attrib[settings.HashFunctionNamespace + 'Hash' + str(i)])

            golden_measurement = GoldenMeasurement(component = self.rim_name,
                                                   values = measurements_values,
                                                   name = child.attrib['name'],
                                                   index = index,
                                                   size = int(child.attrib['size']),
                                                   alternatives = alternatives,
                                                   active = active)
            if index in self.measurements_obj:
                raise InvalidMeasurementIndexError(f"Multiple measurement are assigned same index in {self.rim_name} rim.")
            
            self.measurements_obj[index] = golden_measurement

        if len(self.measurements_obj) == 0:
            raise NoRIMMeasurementsError(f"\tNo golden measurements found in {self.rim_name} rim.\n\tQuitting now.")

        event_log.debug(f"{self.rim_name} golden measurements are : \n\t\t\t\t\t\t\t")
        
        for idx in self.measurements_obj:
            event_log.debug(f"\n\t\t\t\t\t\t\t index : {idx}")
            event_log.debug(f"\t\t\t\t\t\t\t number of alternative values : {self.measurements_obj[idx].get_number_of_alternatives()}")
            for i in range(self.measurements_obj[idx].get_number_of_alternatives()):
                event_log.debug(f"\t\t\t\t\t\t\t\t value {i + 1} : {self.measurements_obj[idx].get_value_at_index(i)}")

        if self.rim_name == 'driver':
            settings.mark_rim_driver_measurements_as_available()
        else:
            settings.mark_rim_vbios_measurements_as_available()

    def get_manufacturer_id(self, driver_rim_content):
        """ Returns the manufacturer id of the RIM.

        Returns:
            [str]: the manufacturer id of the RIM.
        """
        root = etree.fromstring(driver_rim_content)

        ns = {'ns0': 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd',
              'ns1': 'https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/'}
        meta = root.find(".//ns0:Meta", ns)
        firmware_manufacturer_id = meta.attrib[
            '{https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/}FirmwareManufacturerId']
        return firmware_manufacturer_id
        

    def verify(self, version, settings, schema_path = ''): 
        """ Performs the schema validation if it is successful then signature verification is done.
        If both tests passed then returns True, otherwise returns False.
        
        Arguments:
            version (str) : the driver/vbios version of the required RIM.
            settings (config.HopperSettings): the object containing the various config info.
            base_RIM_path (str) : the path to the base RIM. Default value is None.
            schema_path (str) : the path to the swidtag schema xsd file. Default value is "swid_schema_2015.xsd".
        
        Returns :
            [bool] : True if schema validation and signature verification passes, otherwise returns False.
        """
        assert type(version) is str
        assert type(schema_path) is str

        if schema_path == "":
            schema_path = os.path.join(os.path.dirname(__file__), 'swidSchema2015.xsd')

        if not schema_path or not os.path.isfile(schema_path):
            info_log.error("There is a problem in the path to the swid schema. Please provide a valid the path to the swid schema.")
            raise FileNotFoundError("\t\tSWID schema file not found.")

        if self.validate_schema(schema_path = schema_path):
            info_log.info("\t\t\tRIM Schema validation passed.")
            
            if self.rim_name == 'driver':
                settings.mark_driver_rim_schema_validated()
            else:
                settings.mark_vbios_rim_schema_validated()

            if version != self.colloquialVersion.lower():
                info_log.warning(f"\t\t\tThe {self.rim_name} version in the RIM file is not matching with the installed {self.rim_name} version.")
            else:
                if self.rim_name == 'driver':
                    settings.mark_rim_driver_version_as_matching()
                else:
                    settings.mark_rim_vbios_version_as_matching()

                event_log.debug(f"The {self.rim_name} version in the RIM file is matching with the installed {self.rim_name} version.")

            rim_cert_chain = self.extract_certificates()
            # Reading the RIM root certificate.
            with open(os.path.join(settings.ROOT_CERT_DIR, settings.RIM_ROOT_CERT), 'r') as root_cert_file:
                root_cert_data = root_cert_file.read()

            if self.rim_name == 'driver':
                mode = BaseSettings.Certificate_Chain_Verification_Mode.DRIVER_RIM_CERT
            else:
                mode = BaseSettings.Certificate_Chain_Verification_Mode.VBIOS_RIM_CERT

            rim_cert_chain.append(crypto.load_certificate(type = crypto.FILETYPE_PEM, buffer = root_cert_data))
            rim_cert_chain_verification_status = CcAdminUtils.verify_certificate_chain(rim_cert_chain,
                                                                                       settings,
                                                                                       mode)
            if not rim_cert_chain_verification_status:
                raise RIMCertChainVerificationError(f"\t\t\t{self.rim_name} RIM cert chain verification failed")

            info_log.info(f"\t\t\t{self.rim_name} RIM certificate chain verification successful.")

            rim_cert_chain_ocsp_revocation_status, gpu_attestation_warning = CcAdminUtils.ocsp_certificate_chain_validation(rim_cert_chain, settings, mode)

            if not rim_cert_chain_ocsp_revocation_status:
                info_log.error(f"{self.rim_name} RIM cert chain ocsp status verification failed.")
                sys.exit()
            
            return self.verify_signature(settings), gpu_attestation_warning
        
        else:            
            raise RIMSchemaValidationError(f"\t\t\tSchema validation of {self.rim_name} RIM failed.")

    def __init__(self, rim_name, settings, rim_path = '', content = ''):
        """ The constructor method for the RIM class handling all the RIM file processing.

        Args:
            rim_name (str): the name of the RIM, can be either "driver" or "vbios"
            settings (config.HopperSettings): the object containing various config.
            rim_path (str): the path to the RIM file
            content (str): the content of the RIM file as a string.
        Raises:
            InvalidRIMNameError: it is raised if the rim_path is invalid.
        """
        assert type(rim_path) is str
        assert type(rim_name) is str

        if rim_name != 'driver' and rim_name != 'vbios':
            raise InvalidRIMNameError(f"Invalid rim name '{rim_name}' provided, valid names can be 'driver'/'vbios'.")

        self.rim_name = rim_name
        if content == '':
            self.root = RIM.read(base_RIM_path = rim_path)
        else:
            self.root = RIM.read(content = content)

        if rim_name == 'driver':
            settings.mark_driver_rim_fetched()
        else:
            settings.mark_vbios_rim_fetched()
 
        self.colloquialVersion = self.get_colloquial_version()
        self.parse_measurements(settings)
