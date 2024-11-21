#
# SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
import hashlib
import json
import string
import uuid

import jwt
from datetime import datetime, timedelta



class ClaimsUtils:
    """ A class to provide the required functionalities for claims related utility functions
    """

    @staticmethod
    def get_current_switch_claims(settings, switch_uuid: string = ""):
        claims = {'measres': settings.check_if_measurements_are_matching(),
                  "x-nvidia-switch-arch-check": settings.check_if_switch_arch_is_correct(),
                  'x-nvidia-switch-bios-version': settings.check_bios_version(),
                  "x-nvidia-switch-attestation-report-cert-chain-validated": settings.check_if_switch_attestation_report_cert_chain_validated(),
                  "x-nvidia-switch-attestation-report-parsed": settings.check_if_attestation_report_parsed_successfully(),
                  "x-nvidia-switch-attestation-report-nonce-match": settings.check_if_nonce_are_matching(),
                  "x-nvidia-switch-attestation-report-signature-verified": settings.check_if_attestation_report_signature_verified(),
                  "x-nvidia-switch-bios-rim-fetched": settings.check_if_bios_rim_fetched(),
                  "x-nvidia-switch-bios-rim-schema-validated": settings.check_if_bios_rim_schema_validated(),
                  "x-nvidia-switch-bios-rim-cert-validated": settings.check_if_bios_rim_cert_validated(),
                  "x-nvidia-switch-bios-rim-signature-verified": settings.check_if_bios_rim_signature_verified(),
                  "x-nvidia-switch-bios-rim-measurements-available": settings.check_rim_bios_measurements_availability()}
        if settings.check_if_measurements_are_matching() == "success":
            claims["secboot"] = True
            claims["dbgstat"] = "disabled"
        return claims

    @staticmethod
    def get_overall_claims(nonce):
        overallAttestationToken = {}
        overallAttestationToken["sub"] = "NVIDIA-PLATFORM-ATTESTATION"
        overallAttestationToken["nbf"] = datetime.utcnow() - timedelta(seconds=120)
        overallAttestationToken["exp"] = datetime.utcnow() + timedelta(hours=1)
        overallAttestationToken["iat"] = datetime.utcnow()
        overallAttestationToken["jti"] = str(uuid.uuid4())
        overallAttestationToken["x-nvidia-ver"] = "2.0"
        overallAttestationToken["iss"] = "LOCAL_SWITCH_VERIFIER"
        overallAttestationToken["x-nvidia-overall-att-result"] = "false"
        overallAttestationToken["submods"] = {}
        overallAttestationToken["eat_nonce"] = nonce
        return overallAttestationToken

    @staticmethod
    def create_detached_eat_claims(attest_result, switch_claims_list, nonce, hwmodel, ueid, attestation_warnings):
        switch_detached_claims = []
        overall_encoded_claim_arr = ["JWT"]
        overall_claims = ClaimsUtils.get_overall_claims(nonce)
        overall_claims["x-nvidia-overall-att-result"] = attest_result
        switch_claims_dict = {}
        submods_dict = {}
        for i, switch_claims in enumerate(switch_claims_list):
            dict_key = "SWITCH-" + str(i)
            jwt.encode(switch_claims, 'secret', "HS256")
            switch_claims_dict[dict_key] = jwt.encode(switch_claims, 'secret', "HS256")
            switch_claims["eat_nonce"] = nonce
            switch_claims["hwmodel"] = hwmodel[i]
            switch_claims["ueid"] = str(ueid[i])
            switch_claims["iss"] = "LOCAL_SWITCH_VERIFIER"
            if len(attestation_warnings) > 0 and attestation_warnings[i] is not "":
                switch_claims["x-nvidia-attestation-warning"] = attestation_warnings[i]
            switch_claims_json = json.dumps(switch_claims)
            submods_dict[dict_key] = ["DIGEST", ["SHA256", hashlib.sha256(switch_claims_json.encode('utf-8')).hexdigest()]]
            switch_claims["nbf"] = datetime.utcnow() - timedelta(seconds=120)
            switch_claims["exp"] = datetime.utcnow() + timedelta(hours=1)
            switch_claims["iat"] = datetime.utcnow()
            switch_claims["jti"] = str(uuid.uuid4())
            switch_claims["iss"] = "LOCAL_SWITCH_VERIFIER"
            switch_claims_dict[dict_key] = jwt.encode(switch_claims, 'secret', "HS256")
        overall_claims["submods"] = submods_dict
        overall_encoded_claim = jwt.encode(overall_claims,
                                           'secret',
                                           "HS256")
        overall_encoded_claim_arr.append(overall_encoded_claim)
        switch_detached_claims.append(overall_encoded_claim_arr)
        switch_detached_claims.append(switch_claims_dict)
        return switch_detached_claims
