# NVIDIA Attestation SDK

The Attestation SDK offers developers easy-to-use APIs for implementing attestation capabilities into their Python applications. With this SDK, you can seamlessly integrate secure and reliable attestation services into your software, thereby ensuring the authenticity, integrity, and trustworthiness of your system.

The SDK supports:
- Local and Remote GPU Attestation
- Local and Remote NVSwitch Attestation

# Quick Start Guide

## Prerequisites

- GPU SKU that supports Confidential Computing
- Python >= 3.9

**For GPU Attestation:**
- NVIDIA Hopper H100 (or later) GPU that supports CC
- NVIDIA GPU Driver with CC/PPCIE support

**For Switch Attestation:**
- Multiple GPUs connected by NVSwitch
- LS10 Switch supporting PPCIE mode
- NVSwitch Driver with PPCIE support

## Installation

Create a new virtual environment and install Attestation SDK from PyPi repository

    ```
    python3 -m venv venv
    
    source venv/bin/activate
    
    pip3 install nv-attestation-sdk
    ```

## Usage and Examples

- For advanced options and usage details, see the **[Attestation SDK (Python) Documentation](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/sdk_introduction.html)**.
- For complete attestation examples, see the **[Quick Start Guide](https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/hopper_single_gpu.html)**.

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

## Support

- For issues or questions, please [file a bug](https://github.com/NVIDIA/nvtrust/issues). 
- For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com)