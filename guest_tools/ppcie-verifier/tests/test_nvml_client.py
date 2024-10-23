import unittest
from unittest import TestCase
from unittest.mock import patch

import pynvml

from ppcie.verifier.src.nvml.nvml_client import NvmlClient, NvmlSystemConfComputeSettings, \
    NVML_SYSTEM_CONF_COMPUTE_VERSION
from ppcie.verifier.src.utils.status import Status


class NvmlClientTest(TestCase):
    #
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_init(self, mock_nvmlInit):
        nvml_client = NvmlClient()
        # Assert that the nvmlInit method was called
        mock_nvmlInit.assert_called_once()

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlDeviceGetCount")
    def test_get_number_of_gpus(self, nvml_device_get_count, nvml_init):
        # Set the return value of the mock function
        nvml_init.return_value = None
        nvml_device_get_count.return_value = 8

        # Create an instance of NvmlClient
        nvml_client = NvmlClient()

        # Call the method to be tested
        number_of_gpus = nvml_client.get_number_of_gpus()

        # Assert that the method returns the expected value
        self.assertEqual(number_of_gpus, 8)

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    @patch("pynvml.nvmlSystemGetConfComputeGpusReadyState")
    def test_gpu_get_ready_state(self, mock_nvmlSystemGetConfComputeGpusReadyState, mock_init):
        mock_nvmlSystemGetConfComputeGpusReadyState.return_value = 1
        mock_init.return_value = None
        nvml_client = NvmlClient()
        ready_state = nvml_client.get_gpu_ready_state()
        self.assertEqual(ready_state, 1)

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    @patch("ppcie.verifier.src.nvml.nvml_client.NvmlSystemConfComputeSettings")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemGetConfComputeSettings")
    def test_system_configuration_compute_settings(self, mock_system_configuration_compute_settings, mock_settings, mock_init):
        mock_init.return_value = None
        status = Status()
        result = pynvml.NVML_SUCCESS
        settings = NvmlSystemConfComputeSettings()
        settings.version = NVML_SYSTEM_CONF_COMPUTE_VERSION
        settings.environment = 1
        settings.ccFeature = 2
        settings.devToolsMode = 3
        settings.multiGpuMode = 4
        mock_settings.return_value = settings
        mock_system_configuration_compute_settings.return_value = result
        nvml_client = NvmlClient()
        system_configuration_compute_settings, status = nvml_client.get_system_conf_compute_settings(status)
        self.assertEqual(system_configuration_compute_settings.version, NVML_SYSTEM_CONF_COMPUTE_VERSION)
        self.assertEqual(system_configuration_compute_settings.get_cc_feature, 2)
        self.assertEqual(system_configuration_compute_settings.get_multi_gpu_mode, 4)
        self.assertEqual(system_configuration_compute_settings.devToolsMode, 3)
        self.assertEqual(system_configuration_compute_settings.environment, 1)

    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlSystemSetConfComputeGpusReadyState")
    @patch("ppcie.verifier.src.nvml.nvml_client.nvmlInit")
    def test_set_gpu_ready_state(self, mock_init, mock_set_gpu_ready_state):
        mock_init.return_value = None
        mock_set_gpu_ready_state.return_value = pynvml.NVML_SUCCESS
        nvml_client = NvmlClient()
        status = nvml_client.set_gpu_ready_state(True)
        self.assertEqual(status, pynvml.NVML_SUCCESS)
