import logging
import unittest

from verifier.nvml import NvmlHandler

from verifier.config import BaseSettings
from ppcie.verifier.verification import (disable_gpu_state, enable_gpu_state, get_number_of_switches, get_number_of_gpus, generate_nonce, perform_gpu_attestation, perform_switch_attestation, validate_gpu_pre_checks,
                                         validate_switch_pre_checks)
from unittest.mock import patch
import pynvml

from ppcie.verifier.src.nvml.nvml_client import NvmlClient, NvmlSystemConfComputeSettings, \
    NVML_SYSTEM_CONF_COMPUTE_VERSION
from ppcie.verifier.src.utils.status import Status
from ppcie.verifier.verification import verification
import sys
import os
from nv_attestation_sdk import attestation

PPCIE_EVIDENCE = os.environ.get("PPCIE_EVIDENCE")


class TestVerification(unittest.TestCase):

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.switch_topology_check")
    @patch("ppcie.verifier.src.topology.validate_topology.TopologyValidation.gpu_topology_check")
    @patch("nv_attestation_sdk.attestation.Attestation")
    @patch("ppcie.verifier.src.nvml.nvml_client.NvmlSystemConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemGetConfComputeSettings")
    @patch("ppcie.verifier.verification.NSCQHandler")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlDeviceGetCount")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_verification(self, nvml_init, gpu_device_count, nscq_handler, mock_system_configuration_compute_settings, mock_settings, attestation_client, gpu_topology_check, switch_topology_check, get_ready_state, set_ready_state):
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
        attestation_client.return_value = attestation.Attestation('test-name')
        client = attestation.Attestation('test-name')
        client.get_evidence.return_value = [
            {
                    "evidence": PPCIE_EVIDENCE}
            ]
        client.attest.return_value = True
        client.validate_token.return_value = True
        client.clear_verifiers.return_value = None
        attestation.Attestation.return_value = client
        status.topology_checks = True
        status.gpu_pre_checks = True
        status.switch_pre_checks = True
        status.gpu_attestation = True
        status.switch_attestation = True
        gpu_topology_check.return_value = status
        switch_topology_check.return_value = status
        get_ready_state.return_value = 1
        set_ready_state.return_value = pynvml.NVML_SUCCESS
        testargs = ["prog", "--gpu-attestation-mode", "LOCAL", "--switch-attestation-mode", "LOCAL", "--log", "DEBUG"]
        with patch.object(sys, 'argv', testargs):
            verification()

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

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nscq.NSCQHandler")
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

    def test_generate_nonce(self):
        hex = generate_nonce()
        self.assertIsNotNone(hex)
        self.assertTrue(len(hex) == 64)
        self.assertTrue(hex.isalnum())

    @patch("nv_attestation_sdk.attestation.Attestation")
    def test_perform_gpu_attestation(self, attestation_client):
        logger = logging.getLogger('test')
        status = Status()
        attestation_client.return_value = attestation.Attestation('test-name')
        client = attestation.Attestation('test-name')
        client.get_evidence.return_value = [
            {
                "evidence": PPCIE_EVIDENCE}
        ]
        client.attest.return_value = True
        client.validate_token.return_value = True
        client.clear_verifiers.return_value = None
        attestation.Attestation.return_value = client
        status, attestation_report = perform_gpu_attestation(logger, status, {'gpu_attestation_mode': 'REMOTE', 'ocsp_nonce_disabled': 'False'})
        self.assertTrue(status.gpu_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("nv_attestation_sdk.attestation.Attestation")
    def test_perform_switch_attestation(self, attestation_client):
        logger = logging.getLogger('test')
        status = Status()
        attestation_client.return_value = attestation.Attestation('test-name')
        client = attestation.Attestation('test-name')
        client.get_evidence.return_value = [
            {
                "evidence": PPCIE_EVIDENCE}
        ]
        client.attest.return_value = True
        client.validate_token.return_value = True
        client.clear_verifiers.return_value = None
        attestation.Attestation.return_value = client
        status, attestation_report = perform_switch_attestation(logger, status, {'switch_attestation_mode':'REMOTE', 'ocsp_nonce_disabled': 'False'})
        self.assertTrue(status.switch_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("nv_attestation_sdk.attestation.Attestation")
    def test_perform_gpu_attestation_with_ocsp_nonce_disabled(self, attestation_client):
        logger = logging.getLogger('test')
        status = Status()
        attestation_client.return_value = attestation.Attestation('test-name')
        client = attestation.Attestation('test-name')
        client.get_evidence.return_value = [
            {
                "evidence": PPCIE_EVIDENCE}
        ]
        client.attest.return_value = True
        client.validate_token.return_value = True
        client.clear_verifiers.return_value = None
        attestation.Attestation.return_value = client
        status, attestation_report = perform_gpu_attestation(logger, status, {'gpu_attestation_mode': 'REMOTE', 'ocsp_nonce_disabled': 'True'})
        self.assertTrue(status.gpu_attestation)
        self.assertIsNotNone(attestation_report)

    @patch("nv_attestation_sdk.attestation.Attestation")
    def test_perform_switch_attestation_with_ocsp_nonce_disabled(self, attestation_client):
        logger = logging.getLogger('test')
        status = Status()
        attestation_client.return_value = attestation.Attestation('test-name')
        client = attestation.Attestation('test-name')
        client.get_evidence.return_value = [
            {
                "evidence": PPCIE_EVIDENCE}
        ]
        client.attest.return_value = True
        client.validate_token.return_value = True
        client.clear_verifiers.return_value = None
        attestation.Attestation.return_value = client
        status, attestation_report = perform_switch_attestation(logger, status, {'switch_attestation_mode':'REMOTE', 'ocsp_nonce_disabled': 'True'})
        self.assertTrue(status.switch_attestation)
        self.assertIsNotNone(attestation_report)

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

    @patch("nv_attestation_sdk.verifiers.nv_switch_verifier.nscq.NSCQHandler")
    def test_switch_pre_checks(self, nscq_handler):
        status = Status()
        logger = logging.getLogger('test')
        nscq_handler.return_value = None
        nscq_handler.is_switch_tnvl_mode.return_value = 1, 0
        nscq_handler.is_switch_lock_mode.return_value = 1, 0
        result_status = validate_switch_pre_checks(nscq_handler, logger, status, ['switchid-1', 'switchid-2', 'switchid-3', 'switchid-4'])
        self.assertTrue(result_status.switch_pre_checks)
