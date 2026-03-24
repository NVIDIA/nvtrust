# nvTrust: Ancillary Software for NVIDIA Trusted Computing Solutions

[![License](https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue)](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/sdk_introduction.html)
[![Release](https://img.shields.io/github/v/release/NVIDIA/nvtrust)](https://github.com/NVIDIA/nvtrust/releases)
[![PyPI](https://img.shields.io/pypi/v/nv-attestation-sdk.svg)](https://pypi.org/project/nv-attestation-sdk/)
[![Python](https://img.shields.io/badge/python-3.7%20and%20above-orange)](https://pypi.org/project/nv-attestation-sdk/)
[![Issues](https://img.shields.io/github/issues/NVIDIA/nvtrust)](https://github.com/NVIDIA/nvtrust/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/NVIDIA/nvtrust)](https://github.com/NVIDIA/nvtrust/pulls)
[![Stars](https://img.shields.io/github/stars/NVIDIA/nvtrust?style=social)](https://github.com/NVIDIA/nvtrust/stargazers)
[![Forks](https://img.shields.io/github/forks/NVIDIA/nvtrust?style=social)](https://github.com/NVIDIA/nvtrust/network/members)

This repository provides essential resources for implementing and validating Trusted Computing Solutions on NVIDIA hardware. It focuses on attestation, a crucial aspect of ensuring the integrity and security of confidential computing environments.

## Tools and Components

This repository includes the following attestation tools and utilities:

### Guest Tools

- **[Attestation SDK (Python)](guest_tools/attestation_sdk/README.md)** - A comprehensive Python SDK providing easy-to-use APIs for implementing GPU and NVSwitch attestation capabilities into your applications. Supports both local and remote attestation workflows.

- **[Local GPU Verifier](guest_tools/gpu_verifiers/local_gpu_verifier/README.md)** - A standalone tool for local GPU attestation verification. *Note: This tool is now integrated into the Attestation SDK. Please use the Attestation SDK for GPU attestation workflows.*

> **Deprecation Notice:** 
> The Python SDK and the Local GPU Verifier are deprecated. Users are encouraged to use the new [C++ SDK](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/introduction.html) and the [CLI](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html).
> For help with migration to the C++ SDK, see the [Migration Guide](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/migration_guide.html).

- **[PPCIE Verifier](guest_tools/ppcie-verifier/README.md)** - Protected PCIe verifier for multi-GPU confidential computing setups where all GPUs are in PPCIE mode, enabling plain-text NVLink traffic while preserving confidential VM security.

### Host Tools

- **[Host Tools](host_tools/README.md)** - Utilities for configuring GPU Confidential Computing modes and sample KVM scripts for launching Confidential VMs from the host.

## Getting Started with Attestation

To get started and learn more about NVIDIA Attestation, refer to the [NVIDIA Attestation docs](https://docs.nvidia.com/attestation/).

### Quick Start and Deployment Guides

- **[Quick Start Guide](https://docs.nvidia.com/attestation/quick-start-guide/latest/getting_started.html)** - Get up and running quickly with NVIDIA Attestation
- **[Deployment Guide](https://docs.nvidia.com/attestation/poc-to-production/latest/deployment_guide.html)** - Comprehensive guide for deploying attestation from POC to production

### SDK and CLI Documentation

- **[Attestation SDK (Python) Documentation](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/sdk_introduction.html)** - Complete documentation for the Python SDK

- **[PPCIE Verifier Documentation](https://docs.nvidia.com/attestation/attestation-client-tools-ppcie/latest/ppcie_introduction.html)** - Documentation for Protected PCIe attestation

## Contributing

We welcome contributions from the community. Please refer to our [CONTRIBUTE.md](CONTRIBUTE.md) file for guidelines on how to contribute to this project.

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.

## Support

- For issues or questions, please [file a bug](https://github.com/NVIDIA/nvtrust/issues). 
- For additional support, contact us at [attestation-support@nvidia.com](mailto:attestation-support@nvidia.com)
