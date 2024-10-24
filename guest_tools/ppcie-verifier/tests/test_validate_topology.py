from unittest import TestCase
from unittest.mock import Mock, patch

from ppcie.verifier.src.topology.validate_topology import TopologyValidation, GpuAttestationReport
from ppcie.verifier.src.utils.status import Status


class TopologyValidationTest(TestCase):

    def test_topology_init(self):
        topology = TopologyValidation()
        self.assertEqual(topology.opaque_data_field, {})
        self.assertEqual(topology.unique_switches, set())
        self.assertEqual(topology.unique_gpus, set())

    # @patch("ppcie.verifier.src.topology.validate_topology.read_field_as_little_endian")
    @patch("ppcie.verifier.src.topology.validate_topology.GpuAttestationReport")
    def test_gpu_topology_check(self, mock_gpu_attestation_report):
        topology = TopologyValidation()
        mock_gpu_attestation_report.return_value.get_response_message.return_value.get_opaque_data.return_value.get_data.return_value = [b'@\xb9\xc6\xb3\xd7H\xfd\x90', b'\xfd\xb5)\xf1G<\xb2%', b'\x10C\xc1N\x83Y\x96c', b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa']

        gpu_attestation_report_list = [mock_gpu_attestation_report] * 8
        status = Status()
        result_status = topology.gpu_topology_check(
            gpu_attestation_report_list, 4, status
        )
        # Verify the result
        self.assertTrue(result_status.topology_checks)
        self.assertEqual(topology.unique_switches, {'639659834ec14310', '90fd48d7b3c6b940', 'aa0a158e029df6d0', '25b23c47f129b5fd'})

    def get_data_side_effect(arg, twas):
        if twas == "OPAQUE_FIELD_ID_DEVICE_PDI":
            return b'\x90\xfdH\xd7\xb3\xc6\xb9@'
        elif twas == "OPAQUE_FIELD_ID_SWITCH_GPU_PDIS":
            return b'@\xb9\xc6\xb3\xd7H\xfd\x90', b'\xfd\xb5)\xf1G<\xb2%', b"\xbf\\\xc6'\xc8\x13\xae\xd8", b'\xe2\xd8[Y\x0eq2\x98', b'\x10C\xc1N\x83Y\x96c', b'1d\x9c\xf1\x1c\x82\x08X', b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa', b'\xd0\xf6\x9d\x02\x8e\x15\n\xab'
        return None

    @patch("ppcie.verifier.src.topology.validate_topology.GpuAttestationReport")
    @patch("ppcie.verifier.src.topology.validate_topology.SwitchAttestationReport")
    def test_switch_topology_check(self, mock_switch_attestation_report, mock_gpu_attestation_report):
        topology = TopologyValidation()
        mock_gpu_attestation_report.return_value.get_response_message.return_value.get_opaque_data.return_value.get_data.return_value = [b'@\xb9\xc6\xb3\xd7H\xfd\x90', b'\xfd\xb5)\xf1G<\xb2%', b'\x10C\xc1N\x83Y\x96c', b'\xd0\xf6\x9d\x02\x8e\x15\n\xaa']

        mock_switch_attestation_report.return_value.get_response_message.return_value.get_opaque_data.return_value.get_data.side_effect = self.get_data_side_effect
        mock_switch_attestation_report.return_value.get_response_message.return_value.get_opaque_data.return_value.get_data.side_effect = self.get_data_side_effect

        gpu_attestation_report_list = [mock_gpu_attestation_report] * 8
        switch_attestation_report_list = [mock_switch_attestation_report, mock_switch_attestation_report,
                                       mock_switch_attestation_report, mock_switch_attestation_report]
        status = Status()
        topology.gpu_topology_check(gpu_attestation_report_list, 4, status)
        result_status = topology.switch_topology_check(switch_attestation_report_list, 8, status)

        self.assertTrue(result_status.topology_checks)


