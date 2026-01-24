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

import os
from hashlib import sha384

ATTESTATION_SERVICE_KEY = os.getenv("NVIDIA_ATTESTATION_SERVICE_KEY")
DEVICE_ROOT_CERT = os.getenv("NV_DEVICE_ROOT_CERT")
SIZE_OF_NONCE_IN_BYTES = 32
CURRENT_OPAQUE_DATA_VERSION = 0


class HopperSettings:
    """Minimal settings required by GPU attestation parsing within PPCIE.
    """
    signature_length = 96
    HashFunction = sha384
