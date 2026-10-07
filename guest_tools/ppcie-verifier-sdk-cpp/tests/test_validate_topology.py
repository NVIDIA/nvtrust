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
from unittest import TestCase

from ppcie.verifier.src.topology.validate_topology import TopologyValidation
from ppcie.verifier.src.utils.status import Status


class TopologyValidationTest(TestCase):

    SWITCH_PDIS = [
        "90FD48D7B3C6B940",
        "25B23C47F129B5FD",
        "639659834EC14310",
        "AA0A158E029DF6D0",
    ]
    GPU_PDIS = [f"{gpu_index:016X}" for gpu_index in range(1, 9)]

    def gpu_claims(self, switch_pdis=None):
        claims = {
            "x-nvidia-gpu-claims-version": "4.0",
            "x-nvidia-gpu-switch-pdis": switch_pdis or self.SWITCH_PDIS,
        }
        return [claims.copy() for _ in range(8)]

    def switch_claims(self):
        return [
            {
                "x-nvidia-switch-claims-version": "3.0",
                "x-nvidia-switch-pdi": switch_pdi,
                "x-nvidia-switch-gpu-pdis": self.GPU_PDIS,
            }
            for switch_pdi in self.SWITCH_PDIS
        ]

    def test_topology_init(self):
        topology = TopologyValidation()
        self.assertEqual(topology.opaque_data_field, {})
        self.assertEqual(topology.unique_switches, set())
        self.assertEqual(topology.unique_gpus, set())

    def test_mixed_version_claims_validate_full_topology(self):
        topology = TopologyValidation()
        status = Status()

        topology.gpu_topology_check(self.gpu_claims(), 4, status)
        result_status = topology.switch_topology_check(self.switch_claims(), 8, status)

        self.assertTrue(result_status.topology_checks)
        self.assertEqual(topology.unique_switches, set(self.SWITCH_PDIS))
        self.assertEqual(topology.unique_gpus, set(self.GPU_PDIS))

    def test_gpu_topology_check_ignores_disabled_links(self):
        topology = TopologyValidation()
        status = Status()
        switch_pdis = self.SWITCH_PDIS + ["0000000000000000"]
        topology.gpu_topology_check(self.gpu_claims(switch_pdis), 4, status)
        topology.switch_topology_check(self.switch_claims(), 8, status)

        self.assertEqual(topology.unique_switches, set(self.SWITCH_PDIS))

    def test_switch_topology_check_rejects_duplicate_switch_pdis(self):
        topology = TopologyValidation()
        status = Status()
        claims = self.switch_claims()
        claims[-1]["x-nvidia-switch-pdi"] = claims[0]["x-nvidia-switch-pdi"]

        with self.assertRaises(SystemExit):
            topology.switch_topology_check(claims, 8, status)

        self.assertFalse(status.topology_checks)

    def test_gpu_topology_check_rejects_missing_pdi_claim(self):
        topology = TopologyValidation()
        status = Status()
        claims = [{"x-nvidia-gpu-claims-version": "4.0"} for _ in range(8)]

        with self.assertRaises(SystemExit):
            topology.gpu_topology_check(claims, 4, status)

        self.assertFalse(status.topology_checks)
