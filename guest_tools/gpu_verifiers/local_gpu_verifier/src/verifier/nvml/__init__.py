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

"""A module to handle all the nvml api calls for the verifier.
"""
import ctypes
import sys

from pynvml import (
    nvmlInit,
    nvmlDeviceGetArchitecture,
    nvmlDeviceGetBoardId,
    nvmlDeviceGetCount,
    nvmlDeviceGetHandleByIndex,
    nvmlDeviceGetUUID,
    nvmlDeviceGetVbiosVersion,
    nvmlShutdown,
    nvmlSystemGetDriverVersion,
    nvmlDeviceGetConfComputeGpuAttestationReport,
    nvmlSystemSetConfComputeGpusReadyState,
    nvmlSystemGetConfComputeGpusReadyState,
    nvmlSystemGetConfComputeState,
    nvmlSystemGetConfComputeSettings,
    NVML_CC_ACCEPTING_CLIENT_REQUESTS_FALSE,
    NVML_CC_ACCEPTING_CLIENT_REQUESTS_TRUE,
)

from verifier.utils import (
    get_gpu_architecture_value,
    function_wrapper_with_timeout,
)
from verifier.config import (
    BaseSettings,
    info_log,
    event_log,
    __author__,
    __copyright__,
    __version__,
)
from verifier.nvml.gpu_cert_chains import GpuCertificateChains
from verifier.nvml.nvmlHandlerTest import NvmlHandlerTest
from verifier.exceptions import (
    AttestationReportFetchError,
    TimeoutError,
)

NVML_SYSTEM_CONF_COMPUTE_VERSION = 0x1000014


class NvmlHandler:
    """ Class to handle all the pynvml api calls and fetching the GPU information.
    """
    Handles = None

    @classmethod
    def get_number_of_gpus(cls):
        """ A class method to get the number of available gpus and create a
        list of GPU device handles for the available GPUs.

        Returns:
            [int]: number of available GPUs.
        """
        number_of_gpus = function_wrapper_with_timeout([nvmlDeviceGetCount,
                                                        "nvmlDeviceGetCount"],
                                                       BaseSettings.MAX_NVML_TIME_DELAY)
        cls.Handles = list()

        for i in range(number_of_gpus):
            cls.Handles.append(function_wrapper_with_timeout([nvmlDeviceGetHandleByIndex,
                                                              i,
                                                              "nvmlDeviceGetHandleByIndex"],
                                                             BaseSettings.MAX_NVML_TIME_DELAY))
        return number_of_gpus

    @staticmethod
    def close_nvml():
        """ Static method to close the pynvml library.
        """
        function_wrapper_with_timeout([nvmlShutdown, "nvmlShutdown"], BaseSettings.MAX_NVML_TIME_DELAY)

    @staticmethod
    def init_nvml():
        """ Static method to initialize the pynvml library.
        """
        function_wrapper_with_timeout([nvmlInit, "nvmlInit"], BaseSettings.MAX_NVML_TIME_DELAY)

    @staticmethod
    def set_gpu_ready_state(state):
        """ Static method to set GPU state as ready if the input is True otherwise set as not ready to accept workload.
        """
        assert type(state) is bool

        if state:
            ready_state = NVML_CC_ACCEPTING_CLIENT_REQUESTS_TRUE
        else:
            ready_state = NVML_CC_ACCEPTING_CLIENT_REQUESTS_FALSE

        function_wrapper_with_timeout([nvmlSystemSetConfComputeGpusReadyState,
                                       ready_state,
                                       "nvmlSystemSetConfComputeGpusReadyState"],
                                      BaseSettings.MAX_NVML_TIME_DELAY)

    @staticmethod
    def is_cc_enabled():
        """ Static method to check if the confidential compute feature is enabled or not.

        Returns:
            [bool]: returns True if the cc feature is enabled in driver, otherwise
                    returns False.
        """
        state = function_wrapper_with_timeout([nvmlSystemGetConfComputeState,
                                               "nvmlSystemGetConfComputeState"], BaseSettings.MAX_NVML_TIME_DELAY)
        return state.ccFeature != 0

    @staticmethod
    def is_ppcie_mode_enabled():
        """ Static method to check if the ppcie mode is enabled or not.

        Returns:
            [bool]: returns True if the ppcie mode is enabled in driver, otherwise
                    returns False.
        """
        settings = NvmlSystemConfComputeSettings()
        state = function_wrapper_with_timeout([nvmlSystemGetConfComputeSettings, ctypes.byref(settings),
                                               "nvmlSystemGetConfComputeSettings"], BaseSettings.MAX_NVML_TIME_DELAY)
        return settings.multiGpuMode != 0

    @staticmethod
    def is_cc_dev_mode():
        """ Static method to check if the driver is in "CC DEV" mode or not.

        Returns:
            [bool]: returns True if the driver is in CC DEV mode, otherwise
                    returns False.
        """
        state = function_wrapper_with_timeout([nvmlSystemGetConfComputeState,
                                               "nvmlSystemGetConfComputeState"], BaseSettings.MAX_NVML_TIME_DELAY)
        return state.devToolsMode != 0

    @staticmethod
    def get_gpu_ready_state():
        """ Static method to check the GPU state.

        Returns:
            [int]: returns 0 for not ready 1 for ready state.
        """
        state = function_wrapper_with_timeout([nvmlSystemGetConfComputeGpusReadyState,
                                               "nvmlSystemGetConfComputeGpusReadyState"],
                                              BaseSettings.MAX_NVML_TIME_DELAY)
        return state

    def fetch_attestation_report(self, index, nonce):
        """ Fetches the attestation report of the GPU.

        Args:
            index (int): index of the GPU.
            nonce (bytes): then nonce.

        Raises:
            AttestationReportFetchError: it is raised if the attestation report
            could not be fetched.

        Returns:
            [bytes]: the raw attestation report data.
        """

        try:
            attestation_report_struct = function_wrapper_with_timeout([nvmlDeviceGetConfComputeGpuAttestationReport,
                                                                       self.Handles[index],
                                                                       nonce,
                                                                       "nvmlDeviceGetConfComputeGpuAttestationReport"],
                                                                      BaseSettings.MAX_NVML_TIME_DELAY)
            length_of_attestation_report = attestation_report_struct.attestationReportSize
            attestation_report = attestation_report_struct.attestationReport
            attestation_report_data = list()

            for i in range(length_of_attestation_report):
                attestation_report_data.append(attestation_report[i])

            bin_attestation_report_data = bytes(attestation_report_data)

            BaseSettings.mark_attestation_report_as_available()
            return bin_attestation_report_data

        except TimeoutError as err:
            raise TimeoutError("\tThe call to fetch attestation report timed out.")
        except Exception as err:
            info_log.error(err)
            err_msg = "\tSomething went wrong while fetching the attestation report from the gpu."
            event_log.error(err_msg)
            raise AttestationReportFetchError(err_msg)

    def get_driver_version(self):
        """ Fetches the DriverVersion field of the NvmlHandler class object.

        Returns:
            [str]: the driver version.
        """
        return self.DriverVersion

    def get_uuid(self):
        """ Fetches the UUID field of the NvmlHandler class object.

        Returns:
            [str]: the UUID
        """
        return self.UUID

    def get_vbios_version(self):
        """ Fetches the VbiosVersion field of the NvmlHandler class object.

        Returns:
            [str]: the vbios version
        """
        return self.VbiosVersion

    def get_attestation_cert_chain(self):
        """ Fetches the GPU attestation certificate chain from the
        GpuCertificateChains class object.

        Returns:
            [list]: the list of x509 certificates of the certificate chain.
        """
        return self.CertificateChains.GpuAttestationCertificateChain

    def get_attestation_report(self):
        """ Fetches the attestation report data of the NvmlHandler class object.

        Returns:
            [bytes]: the attestation report data.
        """
        return self.AttestationReport

    def get_gpu_architecture(self):
        """ Fetches the name of the current GPU.
        architecture.

        Returns:
            [str]: the GPU architecture.
        """
        return get_gpu_architecture_value(self.GPUArchitecture)

    def init_handle(self):
        """ Fetches the GPU handle for the current GPU index value.
        """
        self.Handles[self.Index] = function_wrapper_with_timeout([nvmlDeviceGetHandleByIndex,
                                                                  self.Index,
                                                                  "nvmlDeviceGetHandleByIndex"],
                                                                 BaseSettings.MAX_NVML_TIME_DELAY)

    def init_driver_version(self):
        """ Fetches and assigns the Driver Version from the driver via pynvml
        api.
        """
        self.DriverVersion = function_wrapper_with_timeout([nvmlSystemGetDriverVersion,
                                                            "nvmlSystemGetDriverVersion"],
                                                           BaseSettings.MAX_NVML_TIME_DELAY)

    def init_board_id(self):
        """ Fetches and assigns the BoardId from the driver via pynvml api.
        """
        self.BoardId = function_wrapper_with_timeout([nvmlDeviceGetBoardId,
                                                      self.Handles[self.Index],
                                                      "nvmlDeviceGetBoardId"],
                                                     BaseSettings.MAX_NVML_TIME_DELAY)

    def init_uuid(self):
        """ Fetches and assigns the UUID of the GPU to the UUID field.
        """
        self.UUID = function_wrapper_with_timeout([nvmlDeviceGetUUID,
                                                   self.Handles[self.Index],
                                                   "nvmlDeviceGetUUID"],
                                                  BaseSettings.MAX_NVML_TIME_DELAY)

    def init_gpu_architecture(self):
        """ Fetches and assigns the GPU device architecture field.
        """
        self.GPUArchitecture = function_wrapper_with_timeout([nvmlDeviceGetArchitecture,
                                                              self.Handles[self.Index],
                                                              "nvmlDeviceGetArchitecture"],
                                                             BaseSettings.MAX_NVML_TIME_DELAY)

    def init_vbios_version(self):
        """ Fetches and assigns the VbiosVersion field via pynvml api.
        """
        self.VbiosVersion = function_wrapper_with_timeout([nvmlDeviceGetVbiosVersion,
                                                           self.Handles[self.Index],
                                                           "nvmlDeviceGetVbiosVersion"],
                                                          BaseSettings.MAX_NVML_TIME_DELAY)

    def __init__(self, index, nonce, settings):
        """ Constructor method for the NvmlHandler class that initializes the
        various field values.

        Args:
            index (int): the index of the NvmlHandler class object.
            nonce (bytes): the nonce for the attestation report.
            settings (config.HopperSettings): the object containing the various config info.
        """
        assert type(index) is int
        assert type(nonce) is bytes and len(nonce) == BaseSettings.SIZE_OF_NONCE_IN_BYTES

        self.Index = index
        self.init_handle()
        self.init_driver_version()
        self.init_board_id()
        self.init_uuid()
        self.init_gpu_architecture()
        self.init_vbios_version()
        self.CertificateChains = GpuCertificateChains(self.Handles[index])
        self.AttestationReport = self.fetch_attestation_report(index, nonce)
        settings.mark_attestation_report_as_available()


class NvmlSystemConfComputeSettings(ctypes.Structure):
    """
    C-like structure that represents the
    nvmlSystemConfComputeSettings structure.

    This class is used to retrieve the compute settings of the system.

    Attributes:
        version (ctypes.c_uint): The version of the device.
        environment (ctypes.c_uint): The current environment.
        ccFeature (ctypes.c_uint): The CC feature mode.
        devToolsMode (ctypes.c_uint): The developer tools mode.
        multiGpuMode (ctypes.c_uint): The multi-GPU mode.
    """

    _fields_ = [
        ("version", ctypes.c_uint),
        ("environment", ctypes.c_uint),
        ("ccFeature", ctypes.c_uint),
        ("devToolsMode", ctypes.c_uint),
        ("multiGpuMode", ctypes.c_uint),
    ]

    def __init__(self):
        super().__init__(version=NVML_SYSTEM_CONF_COMPUTE_VERSION)

    @property
    def get_cc_feature(self):
        """
        A getter method for retrieving the ccFeature property.
        """
        return self.ccFeature

    @property
    def get_multi_gpu_mode(self):
        """
        Return the multi-gpu mode of the device.
        """
        return self.multiGpuMode
