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

from pynvml import (
    NVML_ERROR_UNINITIALIZED,
    NVML_ERROR_TIMEOUT,
    NVML_ERROR_RESET_REQUIRED,
    NVML_ERROR_IN_USE,
    NVML_ERROR_MEMORY,
    NVML_ERROR_NO_DATA,
    NVML_ERROR_INSUFFICIENT_RESOURCES,
    NVMLError,
)

from verifier.exceptions import (
    SignatureVerificationError,
    NonceMismatchError,
    DriverVersionMismatchError,
    AttestationReportFetchError,
    CertChainFetchError,
    RIMSignatureVerificationError,
    RIMVerificationFailureError,
    MeasurementMismatchError,
    RIMSchemaValidationError,
    InvalidMeasurementIndexError,
    VBIOSVersionMismatchError,
)

def is_non_fatal_issue(error):
    """ The function to check if the given error is non fatal or not.

    Args:
        error (Exception): any exception that may be raised.

    Returns:
        [bool]: returns True if the error is non fatal. Otherwise returns
                False.
    """

    if isinstance(error, type(NVMLError(NVML_ERROR_UNINITIALIZED))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_TIMEOUT))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_RESET_REQUIRED))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_IN_USE))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_MEMORY))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_NO_DATA))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_INSUFFICIENT_RESOURCES))) or \
       isinstance(error, NonceMismatchError) or \
       isinstance(error, MeasurementMismatchError):
       return True
    
    return False

def need_to_change_gpu_state(error):
    """ The function to check if there is a need to set the GPU Ready state to
    not ready. 

    Args:
        error (Exception): any exception that may be raised.
    Returns:
        [bool]: returns True if there is a need to change the GPU ready state,
                otherwise returns False.
    """
    
    if isinstance(error, type(NVMLError(NVML_ERROR_UNINITIALIZED))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_TIMEOUT))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_RESET_REQUIRED))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_IN_USE))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_MEMORY))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_NO_DATA))) or \
       isinstance(error, type(NVMLError(NVML_ERROR_INSUFFICIENT_RESOURCES))) or \
       isinstance(error, AttestationReportFetchError) or \
       isinstance(error, SignatureVerificationError) or \
       isinstance(error, DriverVersionMismatchError) or \
       isinstance(error, VBIOSVersionMismatchError) or \
       isinstance(error, CertChainFetchError) or \
       isinstance(error, RIMSchemaValidationError) or \
       isinstance(error, RIMVerificationFailureError) or \
       isinstance(error, RIMSignatureVerificationError) or \
       isinstance(error, InvalidMeasurementIndexError):
       return True
    
    return False
