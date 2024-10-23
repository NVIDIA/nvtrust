#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""NvmlClient class declares functions necessary to
interact with the GPU to get device specific information"""
import ctypes
import sys
import pynvml
from pynvml import (
    nvmlDeviceGetCount,
    nvmlInit,
    nvmlShutdown,
    nvmlSystemGetConfComputeSettings,
    nvmlSystemSetConfComputeGpusReadyState,
)
from timeout_decorator import timeout_decorator

from ..nvml.exceptions import (
    NvmlInitializationError,
    NvmlGetGpuCountException,
    NvmlGetSystemConfComputeSettingsException,
    GpuReadyStateGetterException,
    GpuReadyStateSetterException,
)
from ..utils.logging import get_logger

logger = get_logger()

NVML_SYSTEM_CONF_COMPUTE_VERSION = 0x1000014


class NvmlClient:
    """
    NvmlClient initializes the NVML driver to get device information.
    If initialization or fetching the device information takes longer than
    the specified timeout, a TimeoutError is raised.
    """

    @timeout_decorator.timeout(10, timeout_exception=TimeoutError)
    def __init__(self):
        """
        Initialize the NVML driver within a specified timeout period.

        Raises:
            NvmlInitializationError: If there's an error
            initializing the NVML library.
            TimeoutError: If NVML initialization exceeds the
            specified timeout duration.
        """
        try:
            logger.debug("PPCIE: Initializing NVML driver")
            nvmlInit()
            self.timeout = timeout_decorator.timeout
        except Exception as e:
            raise NvmlInitializationError("Error in Initializing NVML library. Please install the drivers again and "
                                          "re-try") from e

    @timeout_decorator.timeout(10, timeout_exception=TimeoutError)
    def get_number_of_gpus(self):
        """
        Fetches the number of GPUs within a specified timeout period.

        Raises:
            NvmlGetGpuCountException: If there's an error initializing, connecting
            or due to any unexpected error
            TimeoutError: If request exceeds the specified
            timeout duration.
        """
        global number_of_gpus
        try:
            logger.debug("PPCIE: Initiating an NVML call to get number of GPUs")
            number_of_gpus = nvmlDeviceGetCount()
        except Exception as e:
            logger.error(
                "An error occurred while getting the "
                "number of GPUs from NVML library: %s",
                e,
            )
        logger.debug("PPCIE: Number of GPUs present are %d:", number_of_gpus)
        return number_of_gpus

    @timeout_decorator.timeout(10, timeout_exception=TimeoutError)
    def get_gpu_ready_state(self):
        """
        Gets the ready state of a GPU from nvml
        0 - Not ready
        1 - Ready
        """
        state = None
        try:
            logger.debug("PPCIE: Finding the current GPU ready state")
            state = pynvml.nvmlSystemGetConfComputeGpusReadyState()
            logger.debug("PPCIE: GPU ready state is %d", state)
        except Exception as e:
            logger.error(
                "PPCIE: An error occurred while getting the ready state of GPU from NVML library: %s",
                e,
            )
            sys.exit()
        return state

    @timeout_decorator.timeout(10, timeout_exception=TimeoutError)
    def get_system_conf_compute_settings(self, status):
        """
        Gets the Confidential Compute System Settings Mode information of a GPU.

        Raises:
            NvmlGetSystemConfComputeSettingsException: If there's an error getting the confidential compute settings
            TimeoutError: If request exceeds the specified
            timeout duration.
        """
        try:
            logger.debug(
                "PPCIE: Initiating an NVML call to get confidential compute Mode info"
            )
            settings = NvmlSystemConfComputeSettings()
            result = nvmlSystemGetConfComputeSettings(ctypes.byref(settings))
            logger.debug("PPCIE: Response code for getting conf. compute settings is: %d", result)
            if result == pynvml.NVML_SUCCESS:
                logger.debug("PPCIE: Settings retrieved successfully:")
                logger.debug("PPCIE: Version: %d", settings.version)
                logger.debug("PPCIE: Environment: %d", settings.environment)
                logger.debug("PPCIE: CC Feature: %d", settings.ccFeature)
                logger.debug("PPCIE: Dev Tools Mode: %d", settings.devToolsMode)
                logger.debug("PPCIE: Multi-GPU Mode: %d", settings.multiGpuMode)
            else:
                status.gpu_pre_checks = False
                raise NvmlGetSystemConfComputeSettingsException(
                    "PPCIE: An error occurred while getting the confidential compute settings information from NVML "
                    "library",
                    result,
                )
        except Exception as e:
            logger.error(
                "An error occurred while getting the confidential compute settings information from NVML library: %s",
                e,
            )
            status.gpu_pre_checks = False
            sys.exit()
        return settings, status

    @timeout_decorator.timeout(10, timeout_exception=TimeoutError)
    def set_gpu_ready_state(self, state):
        """
        A setter method for setting the gpu ready state.
        :param state:
        :return: gpu_ready_state_status
        """
        try:
            logger.debug("PPCIE: Setting gpu state to %s", state)
            assert isinstance(state, bool)

            if state:
                ready_state = pynvml.NVML_CC_ACCEPTING_CLIENT_REQUESTS_TRUE
            else:
                ready_state = pynvml.NVML_CC_ACCEPTING_CLIENT_REQUESTS_FALSE

            result = nvmlSystemSetConfComputeGpusReadyState(ready_state)
            if result == pynvml.NVML_SUCCESS:
                logger.info("PPCIE: Successfully set gpu state to %s", state)
            return result
        except pynvml.NVMLError as ex:
            if ex.__str__() == "Invalid Argument":
                logger.error(
                    "PPCIE: Failed to set GPU ready state since terminal state has been reached. Please reboot the "
                    "system"
                )
                return None
            else:
                logger.error(
                    "PPCIE: Failed to set gpu ready state due to exception %s", ex
                )
                raise GpuReadyStateSetterException(
                    "PPCIE: Failed to set gpu ready state"
                ) from ex
        except Exception as e:
            logger.error("PPCIE: Failed to set gpu ready state due to exception %s", e)
            raise GpuReadyStateSetterException(
                "PPCIE: Failed to set gpu ready state"
            ) from e

    def __destroy__(self):
        """
        Destroying the nvml driver client after usage.
        """
        nvmlShutdown()


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
