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

import logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization

class SimpleMessageHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            formatted_msg = self.center_message(msg, width=50)  # Adjust width as needed
            stream.write(f"{formatted_msg}\n")
            self.flush()
        except Exception:
            self.handleError(record)

    def center_message(self, msg, width):
        """
        This method constructs a box around a centered message.

        Parameters:
        msg (str): The message to be centered.
        width (int): The total width of the box.

        Returns:
        str: The box with the centered message.

        The box is constructed using asterisks (*) and has a width equal to the input width.
        The message is centered within the box, and the box is padded with spaces around the message.
        If the message is longer than the specified width, it is truncated to fit within the box.
        """
        # Define the total width of the box
        total_width = width
        # Calculate padding
        padding = (
            total_width - len(msg) - 2
        ) // 2  # Subtract 2 for the spaces around the message
        if padding < 0:
            padding = 0
        # Construct the centered message
        centered_msg = f"*{' ' * padding}{msg}{' ' * padding}*"
        if len(centered_msg) < total_width:
            centered_msg = centered_msg[:-1] + "*"
        # Construct the full box with @ symbols
        box_top_bottom = "*" * total_width
        return f"{box_top_bottom}\n{centered_msg}\n{box_top_bottom}"

def read_field_as_little_endian(binary_data):
    """ Reads a multi-byte field in little endian form and return the read
    field as a hexadecimal string.

    Args:
        binary_data (bytes): the data to be read in little endian format.

    Returns:
        [str]: the value of the field as hexadecimal string.
    """
    assert type(binary_data) is bytes
    x = str()
    for i in range(len(binary_data)):
        temp = binary_data[i: i + 1]
        x = temp.hex() + x
    return x


def extract_public_key(certificate):
    """ Reads the leaf certificate of GPU and then extract the public key.

    Args:
        certificate (cryptography.hazmat.backends.openssl.x509._Certificate):
                       the gpu leaf certificate as an cryptography x509 object.

    Returns:
        [bytes]: the public key extracted from the certificate in PEM format.
    """
    assert isinstance(certificate, x509.Certificate)
    public_key = certificate.public_key()
    public_key_in_pem_format = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_in_pem_format
