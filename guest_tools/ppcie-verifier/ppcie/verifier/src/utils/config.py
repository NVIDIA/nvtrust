import os
REMOTE_GPU_VERIFIER_SERVICE_URL = os.getenv("NV_NRAS_GPU_URL", "https://nras.attestation.nvidia.com/v3/attest/gpu")
REMOTE_NVSWITCH_VERIFIER_SERVICE_URL = os.getenv("NV_NRAS_NVSWITCH_URL", "https://nras.attestation.nvidia.com/v3/attest/switch")
RIM_SERVICE_URL = os.getenv("NV_RIM_URL", "https://rim.attestation.nvidia.com/v1/rim/")
OCSP_SERVICE_URL = os.getenv("NV_OCSP_URL", "https://ocsp.ndis.nvidia.com/")
ATTESTATION_SERVICE_KEY = os.getenv("NVIDIA_ATTESTATION_SERVICE_KEY")