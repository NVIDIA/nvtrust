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

class Error(Exception):
    """ Base class for other exceptions.
    """
    pass


class IncorrectProjectError(Error):
    """ It is raised in case of wrong project name is provided as command line 
    argument. 
    """
    pass


class AttestationReportError(Error):
    """ Base class for all exceptions related to attestation report.
    """
    pass


class SignatureVerificationError(AttestationReportError):
    """ It is raised when the signature verification of attestation report fails.
    """
    pass


class NoMeasurementsError(AttestationReportError):
    """ It is raised in case there are no or blank measurement block.
    """
    pass


class ParsingError(AttestationReportError):
    """ It is raised in case of any issues during parsing of the attestation 
    report data.
    """
    pass


class NoMeasurementBlockError(AttestationReportError):
    """ It is raised when there are zero number of measurement blocks.
    """
    pass


class MeasurementSpecificationError(AttestationReportError):
    """ It is raised if any measurement block does not follow DMTF 
    specification.
    """
    pass


class NoCertificateError(AttestationReportError):
    """ It is raised in case there are no certificates in the GPU attestation 
    certificate chain.
    """
    pass


class IncorrectNumberOfCertificatesError(AttestationReportError):
    """ It is raised in case there are unexpected number of certificates in the
    GPU attestation certificate chain.
    """
    pass


class CertChainVerificationFailureError(AttestationReportError):
    """ It is raised in case of the GPU attestation certificate chain
    verification failure.
    """
    pass


class AttestationReportVerificationError(AttestationReportError):
    """ It is raised in case of attestation report signature verification
    failure.
    """
    pass


class NonceMismatchError(AttestationReportError):
    """ It is raised in case the nonce in the SPDM GET MEASUREMENT request
    message is not matching with the generated nonce.
    """
    pass


class DriverVersionMismatchError(AttestationReportError):
    """ It is raised in case the driver version in attestation report is not
    matching with the driver verison fetched from the driver.
    """
    pass


class VBIOSVersionMismatchError(AttestationReportError):
    """ It is raised in case the vbios version in attestation report is not
    matching with the vbios verison fetched from the driver.
    """
    pass


class PynvmlError(Error):
    """ It is the base class for all exceptions related to pynvml.
    """
    pass


class AttestationReportFetchError(PynvmlError):
    """ It is raised in case there is a failure in fetching the Attestation
    report.
    """
    pass


class CertChainFetchError(PynvmlError):
    """ It is raised in case there is a failure in fetching the GPU attestation
    certificate chain.
    """
    pass


class CertExtractionError(PynvmlError):
    """ It is raised in case there is any issue in extracting the individual
    certificates from the certificate chain.
    """
    pass


class UnknownGpuArchitectureError(PynvmlError):
    """ It is raised if the GPU architecture is not correct.
    """
    pass


class UnsupportedGpuArchitectureError(PynvmlError):
    """ It is raised if the GPU architecture is not supported.
    """
    pass


class NoGpuFoundError(PynvmlError):
    """ It is raised in case the number of available GPU is zero.
    """
    pass


class TimeoutError(PynvmlError):
    """ It is raised in case the pynvml api call exceeds the threshold limit.
    """
    pass


class RIMError(Error):
    """ It is a base class for exceptions related to the RIM.
    """
    pass


class RIMFetchError(RIMError):
    """ It is raised in case the required RIM file could not be fetched.
    """
    pass


class ElementNotFoundError(RIMError):
    """ It is raised in case the reqired element is not found in the RIM file.
    """
    pass


class EmptyElementError(RIMError):
    """ It is raised in case the content of an element in the RIM file is empty.
    """
    pass


class RIMSignatureVerificationError(RIMError):
    """ It is raised in case the signature verification of RIM file fails.
    """
    pass


class InvalidCertificateError(RIMError):
    """ It is raised in case there is a problem in extracting the X509 
    certificate from the RIM file.
    """
    pass


class RIMCertChainVerificationError(RIMError):
    """ It is raised in case of the RIM certificate chain verification fails.
    """
    pass


class RIMCertChainOCSPVerificationError(RIMError):
    """ It is raised in case the RIM certificate chain OCSP status verification fails.
    """
    pass


class NoRIMMeasurementsError(RIMError):
    """ It is raised in case there are no measurement values in the RIM file.
    """
    pass


class FileNotFoundError(RIMError):
    """ It is raised in case the required file is not found.
    """
    pass


class RIMVerificationFailureError(RIMError):
    """ It is raised in case the verification of RIM fails.
    """
    pass


class RIMSchemaValidationError(RIMError):
    """ It is raised in case the RIM schema validation fails.
    """
    pass


class InvalidRIMNameError(RIMError):
    """ It is raised in case the name assigned to the RIM class is something
    other than "driver" or "vbios".
    """
    pass

class VerifierError(Error):
    """ It is the base class for the exceptions related to the verifier.
    """
    pass


class MeasurementMismatchError(VerifierError):
    """ It is raised in case any runtime measurement does not matches with the
    golden value.
    """
    pass


class InvalidMeasurementIndexError(VerifierError):
    """ It is raised in case the same measurement value index is active in both
    driver and vbios RIM file.
    """
    pass


class InvalidNonceError(Error):
    """ It is raised if user specified Nonce is not 32 bytes in length.
    """
    pass
