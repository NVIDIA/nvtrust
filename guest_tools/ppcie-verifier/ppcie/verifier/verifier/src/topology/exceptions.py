#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

""" Exceptions for Topology module """

from ..utils.logging import get_logger

logger = get_logger()


class TopologyValidationError(Exception):
    """Base exceptions."""


class ParsingError(TopologyValidationError):
    """ParsingError is thrown when invalid arguments are provided in the attestation report constructor"""


class MeasurementSpecificationError(TopologyValidationError):
    """ParsingError is thrown when invalid arguments are provided in the attestation report constructor"""


class GpuTopologyValidationError(TopologyValidationError):
    """GpuTopologyValidationError is thrown when invalid arguments are provided in the attestation report constructor
    to get switches connected to each GPU"""


class SwitchTopologyValidationError(TopologyValidationError):
    """SwitchTopologyValidationError is thrown when invalid arguments are provided in the attestation report constructor
    to get GPU connected to each Switch"""
