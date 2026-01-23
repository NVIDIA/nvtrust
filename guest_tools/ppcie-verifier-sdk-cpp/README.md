# Protected PCIE Verifier (Version 2.x)

> **Note:** PPCIE Verifier 2.x requires the CPP Attestation SDK and does NOT work with the Python Attestation SDK. See [Prerequisites](#prerequisites) for installation instructions.

## Introduction 

In a multi-GPU confidential computing (CC) setup, NVLink interconnects and NVSwitches are used for GPU to GPU data traffic. NVLink interconnects and NVSwitches are outside the trust boundary and thus should not allow access to plain-text data. All data that flows over NVLink must be encrypted prior to transfer and decrypted at the destination GPU. On the GPU encryption and decryption is performed by the GPU copy engine (CE).

Bouncing through a CE adds constraints and latency to the data path which may result in performance drops for some workloads. 
To minimize performance impact, NVIDIA's 'PPCIE' mode adjusts the security model to trust NVLink data, enabling plain-text traffic without CEs while preserving a Confidential Virtual Machine.

**Note**: There are only two supported GPU usage configurations:
- ALL GPUs are in CC mode. Each GPU can be assigned to one Confidential VM. In this scenario, use the CC verifier.
- ALL GPUs are in PPCIe mode. All GPUs must be assigned one Confidential VM. In this scenario, use the PPCIE verifier.

# Quick Start Guide

## Prerequisites
1. HGX system with 8 GPUs and 4 switches assigned to the single tenant
2. python >= 3.9
3. git installed
4. Nvidia GPU driver installed
5. Nvidia Switch driver installed
6. Nvidia Fabric Manager installed
7. NVIDIA Attestation CLI (`nvattest`) must be installed — follow the [NVIDIA Attestation CLI documentation](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html) (also installs the Attestation CPP SDK).

## Installation

1. Before installing PPCIE Verifier, verify `nvattest` is installed and on your PATH:
    ```
    nvattest version
    ```
        
2. Please elevate to Root User Privileges before installing the packages: (Note: This is necessary to set the GPU ready state)
    ```
    sudo -i
    ```

3. Create a new virtual environment and install PPCIE Verifier from PyPi repository

    ```
    python3 -m venv venv
    
    source venv/bin/activate
    
    pip3 install nv-ppcie-verifier
    ```

## Usage and Examples

- For advanced options and usage details, see the [PPCIE Quick Start Guide](https://docs.nvidia.com/attestation/attestation-client-tools-ppcie-sdk-cpp/latest/ppcie_quickstart_guide.html).

## License
This repository is licensed under Apache License v2.0 except where otherwise noted.

## Support
- For issues or questions, please [file a bug](https://github.com/NVIDIA/nvtrust/issues). 
- For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com)