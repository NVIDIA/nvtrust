# SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import argparse
import unittest
import sys
import os
import json
import base64

from ppcie.verifier.verification import (disable_gpu_state, enable_gpu_state, get_number_of_switches, get_number_of_gpus, perform_gpu_attestation, perform_switch_attestation, validate_gpu_pre_checks,
                                         validate_switch_pre_checks, generate_nonce)
from unittest.mock import patch
import pynvml

from ppcie.verifier.src.nvml.nvml_client import NvmlClient, NvmlSystemConfComputeSettings, NVML_SYSTEM_CONF_COMPUTE_VERSION
from ppcie.verifier.src.utils.status import Status
from ppcie.verifier.verification import verification
import ppcie.verifier.verification as verification_module

class TestVerification(unittest.TestCase):

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.switch_topology_check")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.gpu_topology_check")
    @patch("ppcie.verifier.src.nvml.nvml_client.NvmlSystemConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemGetConfComputeSettings")
    @patch("ppcie.verifier.verification.NSCQHandler")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlDeviceGetCount")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_verification(self, run_nvattest, nvml_init, gpu_device_count, nscq_handler, mock_system_configuration_compute_settings, mock_settings, gpu_topology_check, switch_topology_check, get_ready_state, set_ready_state):
        status = Status()
        nvml_init.return_value = None
        gpu_device_count.return_value = 8
        nscq_handler.return_value = nscq_handler
        nscq_handler.get_all_switch_uuid.return_value = [{'switchid-1', 'switchid-2', 'switchid-3', 'switchid-4'}]
        result = pynvml.NVML_SUCCESS
        settings = NvmlSystemConfComputeSettings()
        settings.version = NVML_SYSTEM_CONF_COMPUTE_VERSION
        settings.environment = 1
        settings.ccFeature = 1
        settings.devToolsMode = 3
        settings.multiGpuMode = 1
        mock_settings.return_value = settings
        mock_system_configuration_compute_settings.return_value = result
        nscq_handler.is_switch_tnvl_mode.return_value = 1, 0
        nscq_handler.is_switch_lock_mode.return_value = 1, 0
        def nvattest_side_effect(logger, command, description):
            if "collect-evidence" in command:
                evidence_item = {"evidences": [{"evidence": base64.b64encode(b"evidence").decode("ascii")}]} 
                return json.dumps(evidence_item), 0
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        status.topology_checks = True
        status.gpu_pre_checks = True
        status.switch_pre_checks = True
        status.gpu_attestation = True
        status.switch_attestation = True
        gpu_topology_check.return_value = status
        switch_topology_check.return_value = status
        get_ready_state.return_value = 1
        set_ready_state.return_value = pynvml.NVML_SUCCESS
        verification_module.parser = argparse.ArgumentParser()
        testargs = ["prog", "--verifier", "local", "--log-level", "debug", "--nonce", "1234", "--relying-party-policy", "/tests/data/relying_party_policy.rego", "--rim-url", "https://rim.attestation.nvidia.com", "--ocsp-url", "https://ocsp.ndis.nvidia.com", "--nras-url", "https://nras.attestation.nvidia.com"]
        with patch.object(sys, 'argv', testargs):
            verification()

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.switch_topology_check")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.gpu_topology_check")
    @patch("ppcie.verifier.src.nvml.nvml_client.NvmlSystemConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemGetConfComputeSettings")
    @patch("ppcie.verifier.verification.NSCQHandler")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlDeviceGetCount")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_verification_with_file_evidence(self, run_nvattest, nvml_init, gpu_device_count, nscq_handler, mock_system_configuration_compute_settings, mock_settings, gpu_topology_check, switch_topology_check, get_ready_state, set_ready_state):
        status = Status()
        nvml_init.return_value = None
        gpu_device_count.return_value = 8
        nscq_handler.return_value = nscq_handler
        nscq_handler.get_all_switch_uuid.return_value = [{'switchid-1', 'switchid-2', 'switchid-3', 'switchid-4'}]
        result = pynvml.NVML_SUCCESS
        settings = NvmlSystemConfComputeSettings()
        settings.version = NVML_SYSTEM_CONF_COMPUTE_VERSION
        settings.environment = 1
        settings.ccFeature = 1
        settings.devToolsMode = 3
        settings.multiGpuMode = 1
        mock_settings.return_value = settings
        mock_system_configuration_compute_settings.return_value = result
        nscq_handler.is_switch_tnvl_mode.return_value = 1, 0
        nscq_handler.is_switch_lock_mode.return_value = 1, 0
        def nvattest_side_effect(logger, command, description):
            if "collect-evidence" in command:
                return "should-not-collect", 1
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        status.topology_checks = True
        status.gpu_pre_checks = True
        status.switch_pre_checks = True
        status.gpu_attestation = True
        status.switch_attestation = True
        gpu_topology_check.return_value = status
        switch_topology_check.return_value = status
        get_ready_state.return_value = 1
        set_ready_state.return_value = pynvml.NVML_SUCCESS
        verification_module.parser = argparse.ArgumentParser()
        testargs = ["prog", "--verifier", "remote", "--log-level", "debug", "--nonce", "1234", "--gpu-evidence", "tests/data/gpu_evidence.json", "--switch-evidence", "tests/data/switch_evidence.json", "--relying-party-policy", "/tests/data/relying_party_policy.rego", "--rim-url", "https://rim.attestation.nvidia.com", "--ocsp-url", "https://ocsp.ndis.nvidia.com", "--nras-url", "https://nras.attestation.nvidia.com"]
        with patch.object(sys, 'argv', testargs):
            verification()

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_gpu_attestation(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                evidence_item = {"evidences": [{"evidence": base64.b64encode(b"gpu_evidence").decode("ascii")}]} 
                return json.dumps(evidence_item), 0
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        status, attestation_report = perform_gpu_attestation(logger, status, {'verifier': 'local', 'log_level': 'info', 'nonce': '1234', 'relying_party_policy': '/tests/data/relying_party_policy.rego', 'rim_url': 'https://rim.attestation.nvidia.com', 'ocsp_url': 'https://ocsp.ndis.nvidia.com', 'nras_url': 'https://nras.attestation.nvidia.com'})
        self.assertTrue(status.gpu_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_switch_attestation(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                evidence_item = {"evidences": [{"evidence": base64.b64encode(b"switch_evidence").decode("ascii")}]} 
                return json.dumps(evidence_item), 0
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        status, attestation_report = perform_switch_attestation(logger, status, {'verifier':'local', 'log_level': 'info', 'nonce': '1234', 'relying_party_policy': '/tests/data/relying_party_policy.rego', 'rim_url': 'https://rim.attestation.nvidia.com', 'ocsp_url': 'https://ocsp.ndis.nvidia.com', 'nras_url': 'https://nras.attestation.nvidia.com'})
        self.assertTrue(status.switch_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_gpu_attestation_with_file_evidence(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                return "should-not-collect", 1
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        args = {
            'verifier': 'remote',
            'log_level': 'info',
            'nonce': '1234',
            'gpu_evidence': 'tests/data/gpu_evidence.json',
            'relying_party_policy': '/tests/data/relying_party_policy.rego',
            'nras_url': 'https://nras.attestation.nvidia.com'
        }
        status, attestation_report = perform_gpu_attestation(logger, status, args)
        self.assertTrue(status.gpu_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_switch_attestation_with_file_evidence(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                return "should-not-collect", 1
            if "attest" in command:
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        args = {
            'verifier': 'remote',
            'log_level': 'info',
            'nonce': '1234',
            'switch_evidence': 'tests/data/switch_evidence.json',
            'relying_party_policy': '/tests/data/relying_party_policy.rego',
            'nras_url': 'https://nras.attestation.nvidia.com'
        }
        status, attestation_report = perform_switch_attestation(logger, status, args)
        self.assertTrue(status.switch_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_gpu_attestation_with_service_key(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        service_key = "test-service-key-123"
        
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                evidence_item = {"evidences": [{"evidence": base64.b64encode(b"gpu_evidence_with_key").decode("ascii")}]} 
                return json.dumps(evidence_item), 0
            if "attest" in command:
                self.assertIn("--service-key", command)
                self.assertIn(service_key, command)
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        args = {
            'verifier': 'local',
            'log_level': 'info',
            'nonce': '1234',
            'rim_url': 'https://rim.attestation.nvidia.com',
            'ocsp_url': 'https://ocsp.ndis.nvidia.com',
            'nras_url': 'https://nras.attestation.nvidia.com',
            'service_key': service_key
        }
        status, attestation_report = perform_gpu_attestation(logger, status, args)
        self.assertTrue(status.gpu_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.verification.run_nvattest_command")
    def test_perform_switch_attestation_with_service_key(self, run_nvattest):
        logger = logging.getLogger('test')
        status = Status()
        service_key = "test-service-key-456"
        
        def nvattest_side_effect(logger_arg, command, description):
            if "collect-evidence" in command:
                evidence_item = {"evidences": [{"evidence": base64.b64encode(b"switch_evidence_with_key").decode("ascii")}]} 
                return json.dumps(evidence_item), 0
            if "attest" in command:
                # Verify that service key is in the command
                self.assertIn("--service-key", command)
                self.assertIn(service_key, command)
                return "ok", 0
            return "", 0
        run_nvattest.side_effect = nvattest_side_effect
        args = {
            'verifier': 'local',
            'log_level': 'info',
            'nonce': '1234',
            'relying_party_policy': '/tests/data/relying_party_policy.rego',
            'rim_url': 'https://rim.attestation.nvidia.com',
            'ocsp_url': 'https://ocsp.ndis.nvidia.com',
            'nras_url': 'https://nras.attestation.nvidia.com',
            'service_key': service_key
        }
        status, attestation_report = perform_switch_attestation(logger, status, args)
        self.assertTrue(status.switch_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_disable_gpu_state(self, nvml_init, get_ready_state, set_ready_state):
        logger = logging.getLogger('test')
        nvml_init.return_value = None
        nvml_client = NvmlClient()
        get_ready_state.return_value = 1
        set_ready_state.return_value = pynvml.NVML_SUCCESS
        disable_gpu_state(logger, nvml_client)
        set_ready_state.assert_called_once()

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_enable_gpu_state(self, nvml_init, get_ready_state, set_ready_state):
        logger = logging.getLogger('test')
        nvml_init.return_value = None
        nvml_client = NvmlClient()
        get_ready_state.return_value = 0
        set_ready_state.return_value = pynvml.NVML_SUCCESS
        enable_gpu_state(logger, nvml_client)
        set_ready_state.assert_called_once()

    @patch("ppcie.verifier.src.nscq.NSCQHandler")
    def test_get_number_of_switches(self, mock_nscq_handler):
        logger = logging.getLogger('test')
        mock_nscq_handler.return_value = None
        mock_nscq_handler.get_all_switch_uuid.return_value = [{'switchid-1', 'switchid-2', 'switchid-3', 'switchid-4'}]
        switch_ids = get_number_of_switches(logger, mock_nscq_handler)
        self.assertEqual(len(switch_ids), 4)

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlDeviceGetCount")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_get_number_of_gpus(self, nvml_init, device_count):
        logger = logging.getLogger('test')
        nvml_init.return_value = None
        device_count.return_value = 8
        nvml_client = NvmlClient()
        number_of_gpus = get_number_of_gpus(logger, nvml_client)
        self.assertEqual(number_of_gpus, 8)

    @patch("ppcie.verifier.src.nvml.nvml_client.NvmlSystemConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemGetConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_gpu_pre_checks(self, nvml_init, mock_system_configuration_compute_settings, mock_settings):
        status = Status()
        logger = logging.getLogger('test')
        nvml_init.return_value = None
        result = pynvml.NVML_SUCCESS
        settings = NvmlSystemConfComputeSettings()
        settings.version = NVML_SYSTEM_CONF_COMPUTE_VERSION
        settings.environment = 1
        settings.ccFeature = 2
        settings.devToolsMode = 3
        settings.multiGpuMode = 1
        mock_settings.return_value = settings
        mock_system_configuration_compute_settings.return_value = result
        nvml_client = NvmlClient()
        result_status = validate_gpu_pre_checks(nvml_client, logger, status)
        self.assertTrue(result_status.gpu_pre_checks)

    @patch("ppcie.verifier.src.nscq.NSCQHandler")
    def test_switch_pre_checks(self, nscq_handler):
        status = Status()
        logger = logging.getLogger('test')
        nscq_handler.return_value = None
        nscq_handler.is_switch_tnvl_mode.return_value = 1, 0
        nscq_handler.is_switch_lock_mode.return_value = 1, 0
        result_status = validate_switch_pre_checks(nscq_handler, logger, status, ['switchid-1', 'switchid-2', 'switchid-3', 'switchid-4'])
        self.assertTrue(result_status.switch_pre_checks)

    def test_generate_nonce(self):
        hex = generate_nonce()
        self.assertIsNotNone(hex)
        self.assertTrue(len(hex) == 64)
        self.assertTrue(hex.isalnum())