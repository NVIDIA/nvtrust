#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.


"""This module declares the base exceptions and inherited
exceptions for NVML client interactions"""

import pynvml

from ..utils.logging import get_logger

logger = get_logger()


class NvmlException(Exception):
    """Base exceptions."""


class NvmlInitializationError(NvmlException):
    """NvmlInitializationError is thrown when the user faces issues
    while using the nvml client for initialization"""


class NvmlGetGpuCountException(NvmlException):
    """NvmlGetGpuCountException is thrown when the user faces issues
    while using the nvml client for getting number of GPUs"""


class GpuReadyStateSetterException(NvmlException):
    """GpuReadyStateSetterExcpetion is thrown when the user faces issues
    while using the nvml client for setting the ready state of the GPU"""


class GpuReadyStateGetterException(NvmlException):
    """GpuReadyStateGetterExcpetion is thrown when the user faces issues
    while using the nvml client for getting the ready state of the GPU"""


class NvmlGetSystemConfComputeSettingsException(NvmlException):
    """NvmlGetSystemConfComputeSettingsException is thrown when the user faces issues
    while using the nvml client for getting the confidential compute system settings info
    """

    def __init__(self, message, result):
        if result == pynvml.NVML_ERROR_UNINITIALIZED:
            logger.error(
                "%s as the library is not initialized correctly: %s", message, result
            )
        elif result == pynvml.NVML_ERROR_INVALID_ARGUMENT:
            logger.error(
                "%s as device is invalid or counter is null  %s",
                message,
                result,
            )
        elif result == pynvml.NVML_ERROR_NOT_SUPPORTED:
            logger.error(
                "%s as the device does not support this feature: %s",
                message,
                result,
            )
        elif result == pynvml.NVML_ERROR_GPU_IS_LOST:
            logger.error(
                "%s the target GPU has fallen off the bus or is otherwise inaccessible: %s",
                message,
                result,
            )
        elif result == pynvml.NVML_ERROR_ARGUMENT_VERSION_MISMATCH:
            logger.error(
                "%s if the provided version is invalid/unsupported: %s",
                message,
                result,
            )
        elif result == pynvml.NVML_ERROR_UNKNOWN:
            logger.error(
                "%s as there is an unknown/unexpected error: %s",
                message,
                result,
            )
        else:
            logger.error(
                "This is an unknown error occured while getting confidential "
                "compute settings information from NVML library"
            )
