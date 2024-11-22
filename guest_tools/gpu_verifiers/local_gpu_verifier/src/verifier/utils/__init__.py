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

import queue
from queue import Empty
from threading import (
    Thread,
    Event,
)

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from verifier.config import (
    event_log,
    info_log,
    BaseSettings,
    __author__,
    __copyright__,
    __version__,
)

from verifier.exceptions import (
    UnknownGpuArchitectureError,
    TimeoutError,
)


def get_gpu_architecture_value(nvml_arch_value):
    """ A function to map the NVML architecture integer value to the
    corresponding architecture name.

    Args:
        nvml_arch_value (int): nvml architecture integer value.

    Raises:
        UnknownGpuArchitectureError: it is raised if the given value does not
                                    correspondes to any known GPU architecture.

    Returns:
        [str]: The corresponding the GPU architecture name.
    """
    if nvml_arch_value == 2:
        return "KEPLER"
    elif nvml_arch_value == 3:
        return "MAXWELL"
    elif nvml_arch_value == 4:
        return "PASCAL"
    elif nvml_arch_value == 5:
        return "VOLTA"
    elif nvml_arch_value == 6:
        return "TURING"
    elif nvml_arch_value == 7:
        return "AMPERE"
    elif nvml_arch_value == 9:
        return "HOPPER"
    else:
        event_log.error("Unknown GPU architecture.")
        raise UnknownGpuArchitectureError("Unknown GPU architecture.")


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


def convert_string_to_blob(inp):
    """ A function to convert the input string of byte values to bytes data type.

    Args:
        inp (str): the input string

    Returns:
        [bytes]: the corresponding binary data.
    """
    assert type(inp) is str

    out = inp.replace(" ", "")
    out = out.replace("\n", "")
    out = out.replace("0x", "")
    out = out.replace("\\x", "")
    out = bytes.fromhex(out)
    return out


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


def is_zeros(x):
    """ This function checks if all the character are zeros of the given input
    string.

    Args:
        x (str): the input string.

    Returns:
        [bool]: True if all the characters are '0', otherwise False.
    """
    assert type(x) is str

    for i in range(len(x)):
        if x[i] != '0':
            return False

    return True


def format_vbios_version(version):
    """ Converts the input VBIOS version to xx.xx.xx.xx.xx format.

    Args:
        version (bytes): the VBIOS version

    Returns:
        [str]: the vbios version in the required format.
    """
    assert type(version) is bytes

    value = read_field_as_little_endian(version)
    temp = value[len(value) // 2:] + value[len(value) // 2 - 2: len(value) // 2]

    idx = 0
    result = str()
    for i in range(0, len(temp) - 2, 2):
        result = result + temp[i: i + 2] + "."
        idx = i + 2
    result = result + temp[idx: idx + 2]

    return result


def function_caller(inp):
    """ This function is run in a separate thread by
    function_wrapper_with_timeout function so that if the execution of the
    function passed as an argument takes more than the max threshold time limit then
    the thread is killed.

    Args:
        inp (tuple): the tuple containing the function to be executed and its
                     arguments.
    """
    assert type(inp) is list

    event = inp[-1]
    q = inp[-2]
    function_name = inp[-3]
    function = inp[0]
    arguments = inp[1:-3]

    result = function(*arguments)

    if event.is_set():
        event_log.info(f"{function_name} execution timed out, stopping.")
        return

    q.put(result)


def function_wrapper_with_timeout(args, max_time_delay):
    """ This function spawns a separate thread for the given function in the
    arguments to be executed in that separate thread.

    Args:
        args (list): the list containing the function and its arguments.

    Raises:
        TimeoutError: it is raised if the thread spawned takes more time than
                      the threshold time limit.

    Returns:
        [any]: the return of the function being executed in the thread.
    """
    assert type(args) is list
    try:
        function_name = args[-1]
        q = queue.Queue()
        args.append(q)
        event = Event()
        args.append(event)
        args = ((args),)
        event_log.info(f"{function_name} called.")
        thread = Thread(target=function_caller, args=args)
        thread.start()
        return_value = q.get(block=True, timeout=max_time_delay)
        event.set()
        return return_value
    except Empty:
        event_log.error(f"The {function_name} call timed out.")
        raise TimeoutError(f"The {function_name} call timed out.")
