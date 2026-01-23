# Protected PCIE Verifier (Version 1.x)

**Note**: PPCIE Verifier version 1.x is deprecated and only supports the Python SDK. For the latest version 2.x with enhanced features, see [PPCIE Verifier SDK CPP](../ppcie-verifier-sdk-cpp/README.md).

## Introduction 

In a multi-GPU confidential computing (CC) setup, NVLink interconnects and NVSwitches are used for GPU to GPU data traffic. NVLink interconnects and NVSwitches are outside the trust boundary and thus should not allow access to plain-text data. All data that flows over NVLink must be encrypted prior to transfer and decrypted at the destination GPU. On the GPU encryption and decryption is performed by the GPU copy engine (CE).

Bouncing through a CE adds constraints and latency to the data path which may result in performance drops for some workloads. To minimize performance impact, NVIDIA's 'PPCIE' mode adjusts the security model to trust NVLink data, enabling plain-text traffic without CEs while preserving a Confidential Virtual Machine.

**Note**: There are only two supported GPU usage configurations: 
- ALL GPUs are in CC mode. Each GPU can be assigned to one Confidential VM. In this scenario, use the CC verifier. 
- ALL GPUs are in PPCIe mode. All GPUs must be assigned one Confidential VM. In this scenario, use the PPCIE verifier

# Quick Start Guide

## Prerequisites
- HGX system with 8 GPUs and 4 switches assigned to the single tenant
- python >= 3.9
- git installed
- Nvidia GPU driver installed
- Nvidia Switch driver installed
- Nvidia Fabric Manager installed

## Installation

1. Please elevate to Root User Privileges before installing the packages: (Note: This is necessary to set the GPU ready state)      

    ```
    sudo -i
    ```
2. Create a new virtual environment and install PPCIE Verifier from PyPi repository

    ```
    python3 -m venv venv
    
    source venv/bin/activate
    
    # This installs version 1.x 
    pip3 install "nv-ppcie-verifier>=1.0,<2.0"
    ```
## Usage and Examples

- For advanced options and usage details, see the **[PPCIE Quick Start Guide](https://docs.nvidia.com/attestation/attestation-client-tools-ppcie/latest/ppcie_quickstart_guide.html)**.
- For a complete end-to-end PPCIE attestation example, see the **[Hopper Multi-GPU (PPCIE) Attestation Example](https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/hopper_ppcie.html)**.

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

## Support

- For issues or questions, please [file a bug](https://github.com/NVIDIA/nvtrust/issues). 
- For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com)