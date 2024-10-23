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

from OpenSSL import crypto
import re
import base64
from ..config import (
    BaseSettings,
)
from ..nvswitch_admin_utils import NVSwitchAdminUtils
from ..exceptions import CertExtractionError


def extract_cert_chain(bin_cert_chain_data):
    """ A static method that takes in the raw data coming in from the nvml api as the switch certificate chain in PEM format
    and then parse it to extract the individual certificates from the certificate chain.

    Args:
        bin_cert_chain_data (bytes): the certificate chain in PEM format.

    Returns:
        [list] : List of the certificates extracted from the given cert chain.
    """
    try:
        assert type(bin_cert_chain_data) is bytes

        PEM_CERT_END_DELIMITER = '-----END CERTIFICATE-----'
        start_index = 0
        end_index = None

        str_data = bin_cert_chain_data.decode()
        cert_obj_list = list()

        for itr in re.finditer(PEM_CERT_END_DELIMITER, str_data):
            end_index = itr.start()
            cert_obj_list.append(crypto.load_certificate(crypto.FILETYPE_PEM, \
                                                         str_data[
                                                         start_index: end_index + len(PEM_CERT_END_DELIMITER)]))

            start_index = end_index + len(PEM_CERT_END_DELIMITER) + len('\n')

            if len(str_data) < start_index:
                break
        return cert_obj_list

    except Exception as err:
        info_log.error(err)
        err_msg = "\tSomething went wrong while extracting the individual certificates from the certificate chain."
        event_log.error(err_msg)
        raise CertExtractionError(err_msg)


def extract_switch_cert_chain_base64(switch_attestation_cert_chain):
    """ Method to extract Switch Certificate Chain and convert that to base64 encoded string

    Args:
        switch_attestation_cert_chain: Switch Certificate Chain from the Attestation Report

    Returns:
        base64 encoded Switch Certificate Chain
    """
    cert_chain_data = ""
    for certificate in switch_attestation_cert_chain:
        cert = certificate.to_cryptography()
        py_open_ssl_cert = NVSwitchAdminUtils.convert_cert_from_cryptography_to_pyopenssl(cert)
        cert_chain_data += crypto.dump_certificate(crypto.FILETYPE_PEM, py_open_ssl_cert).decode()
    cert_chain_bytes = cert_chain_data.encode("ascii")
    encoded_cert_chain = base64.b64encode(cert_chain_bytes)
    encoded_cert_chain = encoded_cert_chain.decode('utf-8')
    return encoded_cert_chain


def get_switch_cert_chain(switch_cert_chain):
    switch_att_cert_chain = extract_cert_chain(switch_cert_chain[0])[:-1]
    with open(BaseSettings.DEVICE_ROOT_CERT, 'r') as f:
        data = f.read()
        switch_att_cert_chain.append(crypto.load_certificate(type=crypto.FILETYPE_PEM, buffer=data))
    return switch_att_cert_chain

