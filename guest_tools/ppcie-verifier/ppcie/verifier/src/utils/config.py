import os
REMOTE_GPU_VERIFIER_SERVICE_URL = os.getenv("NV_NRAS_GPU_URL", "https://nras.attestation.nvidia.com/v3/attest/gpu")
REMOTE_NVSWITCH_VERIFIER_SERVICE_URL = os.getenv("NV_NRAS_NVSWITCH_URL", "https://nras.attestation.nvidia.com/v3/attest/nvswitch")