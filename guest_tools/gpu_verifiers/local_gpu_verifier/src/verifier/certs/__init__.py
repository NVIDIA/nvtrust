#
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

import asn1
from types import SimpleNamespace

class FwidAsn1Parser:
    """ A class to handle the parsing of binary data in ASN1 encoding in the Tag Length Value (TLV) format.
    """

    NUMBER_MAP = {
        0 : "reserved for BER",
        1 : "BOOLEAN",
        2 : "INTEGER",
        3 : "BIT STRING",
        4 : "OCTET STRING",
        5 : "NULL",
        6 : "OBJECT IDENTIFIER",
        7 : "ObjectDescriptor",
        8 : "INSTANCE OF",
        9 : "REAL",
        10 : "ENUMERATED",
        11 : "EMBEDDED PDV",
        12 : "UTF8String",
        13 : "RELATIVE-OID",
        16 : "SEQUENCE",
        17 : "SET",
        18 : "NumericString",
        19 : "PrintableString",
        20 : "TeletexString",
        21 : "VideotexString",
        22 : "IA5String",
        23 : "UTCTime",
        24 : "GeneralizedTime",
        25 : "GraphicString",
        26 : "VisibleString",
        27 : "GeneralString",
        28 : "UniversalString",
        29 : "CHARACTER STRING",
        30 : "BMPString",
    }

    @staticmethod
    def parse_tag(value):
        """ A static function that takes single byte data as integer to prase it as ANS1 Tag.

        Args:
            value (int): the input data

        Raises:
            ValueError: it is raised if the input is not of integer data type

        Returns:
            (types.SimpleNamespace): An object containing the class, form, tag name info of the prased tag data.
        """
        if not isinstance(value, int):
            raise ValueError(f"Expected integer data as input, received {type(value)}")
            
        cls = None
        form = None
        number = None
        tag_name = None
        
        
        bit_5 = ((value >> 5) & 0b1) == 1
        bit_6 = ((value >> 6) & 0b1) == 1
        bit_7 = ((value >> 7) & 0b1) == 1
        
        # CLASS
        if bit_7 and bit_6:
            cls = "PRIVATE"
        elif bit_7 and not bit_6:
            cls = "CONTEXT-SPECIFIC"
        elif not bit_7 and bit_6:
            cls = "APPLICATION"
        else:
            cls = "UNIVERSAL"
        
        # FORM
        if bit_5:
            form = "CONSTRUCTED"
        else:
            form = "PRIMITIVE"
        
        # NUMBER
        number = value & 0b000011111
        tag_name = FwidAsn1Parser.NUMBER_MAP[number]
        
        if cls == "CONTEXT-SPECIFIC":
            tag_name = "CONTEXT-SPECIFIC_TAG"
        
        return SimpleNamespace(cls=cls, form=form,tag_name=tag_name)
    
    @staticmethod
    def parse(data, init_offset):
        """ A static function for parsing of binary data in ASN1 encoding in the Tag Length Value (TLV) format.

        Args:
            data (bytes): the input data
            init_offset (int): the starting offset of the data field.

        Raises:
            ValueError: it is raised in case of invalid input data.

        Returns:
            (types.SimpleNamespace): an object containing the tag, length, value and the end offset of the parsed data. 
        """
        is_sequence = False
        
        if not isinstance(data, bytes) or len(data) < 2:
            raise ValueError("Invalid data encountered while parsing asn1 encoded data.")

        index = init_offset
        tag = FwidAsn1Parser.parse_tag(int.from_bytes(data[index: index + 1], byteorder='big'))
        index += 1
        if tag.tag_name == "SEQUENCE":
            is_sequence = True
        
        if not is_sequence:
            length = int.from_bytes(data[index : index + 1], byteorder='big')
        else:
            length = 0
        index += 1
        
        value = data[index : index + length]
        
        index += length
        
        return SimpleNamespace(tag=tag, length=length, value=value, end_index = index)
    
    @staticmethod
    def asn1_decode(data):
        """ A static function that wraps the asn1 decode function.

        Args:
            data (bytes): the input data

        Raises:
            ValueError: it is raised in case of invalid input data.

        Returns:
            (types.SimpleNamespace): an object containing the tag, and value. 
        """
        if not isinstance(data, bytes):
            raise ValueError(f"Expected bytes data as input, received {type(data)}")
        
        decoder = asn1.Decoder()
        decoder.start(data)
        tag, value = decoder.read()
        return SimpleNamespace(tag=tag, value=value)

class FWID:
    """ A class to encapsulate the FWID data in the and the parsing logic for the data in the AK cert extension.
    """

    NUMBER_OF_FWIDS = 2
    
    def __init__(self, data):
        self.fwid_obj = {}
        index = 0
        
        for i in range(self.NUMBER_OF_FWIDS):
            fwid_dict = {
                "hashAlg" : None,
                "digest" : None,
            }
            
            header = FwidAsn1Parser.parse(data, index)
            index  = header.end_index

            hashAlg = FwidAsn1Parser.parse(data, index)
            index = hashAlg.end_index
        

            digest = FwidAsn1Parser.parse(data, index)
            index  = digest.end_index

            fwid_dict['hashAlg'] = hashAlg
            fwid_dict['digest'] = digest
            
            self.fwid_obj["fwid_" + str(i)] = fwid_dict
        
    def get_fwid(self, index):
        """ A method to return the FWID value at a given index.

        Args:
            index (int): the index of the FWID data.

        Returns:
            (str): the hex string of the fwid value at the given index.
        """
        if not index in range(self.NUMBER_OF_FWIDS):
            raise ValueError(f"Invalid fwid index, the valid range of index is : 0 to {self.NUMBER_OF_FWIDS}")

        return self.fwid_obj["fwid_" + str(index)]['digest'].value

class TcbInfoExtension:
    """ A class to parse the TcbInfoExtension of the AK cert.
    """
    
    def __init__(self, data):

        if not isinstance(data, bytes):
            raise ValueError(f"Expected bytes data as input, received {type(data)}")

        data = FwidAsn1Parser.asn1_decode(data).value

        self.result = {}
        idx = 0
    
        vendor = FwidAsn1Parser.asn1_decode(data)
        self.result['vendor'] = vendor.value
        idx = idx + 2 + len(vendor.value)

        model = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['model'] = model.value
        idx = idx + 2 + len(model.value)

        version = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['version'] = version.value
        idx = idx + 2 + len(version.value)

        svn = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['svn'] = svn.value
        idx = idx + 2 + len(svn.value)

        layer = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['layer'] = layer.value
        idx = idx + 2 + len(layer.value)

        index = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['index'] = index.value
        idx = idx + 2 + len(index.value)

        fwids = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['fwids'] = FWID(fwids.value)
        idx = idx + 2 + len(fwids.value)
        
        flags = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['flags'] = flags.value
        idx = idx + 2 + len(flags.value)
        
        vendorInfo = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['vendorInfo'] = vendorInfo.value
        idx = idx + 2 + len(vendorInfo.value)
        
        Type = FwidAsn1Parser.asn1_decode(data[idx:])
        self.result['type'] = Type.value
        idx =  idx + 2 + len(Type.value)