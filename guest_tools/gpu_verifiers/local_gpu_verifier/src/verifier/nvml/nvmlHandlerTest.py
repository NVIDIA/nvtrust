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

from pynvml import (
    NVML_DEVICE_ARCH_HOPPER,
)

from verifier.utils import (
    get_gpu_architecture_value,
    convert_string_to_blob,
)
from verifier.config import (
    BaseSettings,
    HopperSettings,
    __author__,
    __copyright__,
    __version__,
)
from verifier.nvml import GpuCertificateChains
from verifier.nvml.test_handle import TestHandle
from verifier.exceptions import (
    CertExtractionError,
    UnsupportedGpuArchitectureError,
)

class NvmlHandlerTest:

    @classmethod
    def get_number_of_gpus(cls):
        return BaseSettings.TEST_NO_GPU_NUMBER_OF_GPUS

    def extract_cert_chain(self, bin_cert_chain_data):
        try:
            assert type(bin_cert_chain_data) is bytes

            PEM_CERT_END_DELIMITER = '-----END CERTIFICATE-----'
            start_index = 0
            end_index = None

            # length of \n is 1
            length_of_new_line = 1
            
            str_data = bin_cert_chain_data.decode()
            cert_obj_list = list()

            for itr in re.finditer(PEM_CERT_END_DELIMITER, str_data):
                end_index = itr.start()
                cert_obj_list.append(crypto.load_certificate(crypto.FILETYPE_PEM, \
                                    str_data[start_index : end_index + len(PEM_CERT_END_DELIMITER)]))

                start_index = end_index + len(PEM_CERT_END_DELIMITER) + length_of_new_line

                if len(str_data) < start_index:
                    break

            return cert_obj_list
        except Exception as err:
            raise CertExtractionError("\tSomething went wrong while extracting the individual certificates from the certificate chain.\n\tQuitting now.")
    
    def fetch_attestation_report(self):

        if self.GPUArchitecture == NVML_DEVICE_ARCH_HOPPER:
            path = HopperSettings.ATTESTATION_REPORT_PATH
        else:
            raise UnsupportedGpuArchitectureError("Only HOPPER architecture is supported.")
    
        with open(path, 'r') as f:
            data = convert_string_to_blob(f.read())
        return data

    def get_driver_version(self):
        return self.DriverVersion

    def get_vbios_version(self):
        return self.VbiosVersion

    def get_test_attestation_cert_chain(self):

        if self.GPUArchitecture == NVML_DEVICE_ARCH_HOPPER:
            path = HopperSettings.GPU_ATTESTATION_CERTIFICATES_PATH
        else:
            raise UnsupportedGpuArchitectureError("Only HOPPER architecture is supported.")

        with open(path, 'rb') as f:
            data = f.read()
        
        return data

    def get_attestation_cert_chain(self):
        return self.CertificateChains.GpuAttestationCertificateChain

    def get_attestation_report(self):
        return self.AttestationReport
    
    def get_gpu_architecture(self):
        return get_gpu_architecture_value(self.GPUArchitecture)

    def get_uuid(self):
        return self.UUID

    def __init__(self, settings):
        self.GPUArchitecture = NVML_DEVICE_ARCH_HOPPER
        self.BoardId = 11111
        self.Index = 0
        self.UUID = 'GPU-11111111-2222-3333-4444-555555555555'
        self.VbiosVersion = "96.00.5e.00.01"
        self.DriverVersion = "545.00"
        self.AttestationReport = self.fetch_attestation_report()
        settings.mark_attestation_report_as_available()
        cert_data = self.get_test_attestation_cert_chain()
        handle = TestHandle(cert_data)
        self.CertificateChains = GpuCertificateChains(handle)
