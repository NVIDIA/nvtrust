#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.


"""This module declares the generic base exceptions and inherited
exceptions for PPCIE interactions"""

from ..utils.logging import get_logger

logger = get_logger()


class PpcieVerifierException(Exception):
    """PpcieVerifierException is thrown when the user faces issues
    while using the ppcie-verifier to verify the GPUs/Nvswitches"""


class GpuPreChecksException(PpcieVerifierException):
    """GpuPreChecksException is thrown when the user faces issues
    while using the ppcie-verifier to verify the TNVL mode of the GPUs"""


class SwitchPreChecksException(PpcieVerifierException):
    """SwitchPreChecksException is thrown when the user faces issues
    while using the ppcie-verifier to verify the TNVL/LOCK mode of the Switches"""


class GpuAttestationException(PpcieVerifierException):
    """GpuAttestationException is thrown when the user faces issues
    while using the ppcie-verifier to attest the GPUs"""


class SwitchAttestationException(PpcieVerifierException):
    """SwitchAttestationException is thrown when the user faces issues
    while using the ppcie-verifier to attest the Switches"""
