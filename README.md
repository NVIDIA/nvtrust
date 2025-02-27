# nvTrust: Ancillary Software for NVIDIA Trusted Computing Solutions

This repository provides essential resources for implementing and validating Trusted Computing Solutions on NVIDIA hardware. It focuses on attestation, a crucial aspect of ensuring the integrity and security of confidential computing environments.

For more information, including documentation, white papers, and videos regarding NVIDIA Confidential Computing, please visit [NVIDIA docs](https://docs.nvidia.com/confidential-computing/index.html).

## Getting Started with Attestation

To begin using NVIDIA GPU attestation, please refer to [this documentation](./guest_tools/README.md). This guide will walk you through:

- Setting up the necessary environment
- Implementing attestation in your applications
- Validating the attestation process

## Confidential Computing

NVIDIA Confidential Computing offers a solution for securely processing data and code in use, preventing unauthorized users from both access and modification. When running AI training or inference, the data and the code must be protected. Often the input data includes personally identifiable information (PII) or enterprise secrets, and the trained model is highly valuable intellectual property (IP). Confidential computing is the ideal solution to protect both AI models and data.

NVIDIA is at the forefront of confidential computing, collaborating with CPU partners, cloud providers, and independent software vendors (ISVs) to ensure that the change from traditional, accelerated workloads to confidential, accelerated workloads will be smooth and transparent.

For more information, including documentation, white papers, and videos regarding the Hopper Confidential Computing story, please visit [NVIDIA docs](https://docs.nvidia.com/confidential-computing/index.html).

## Release Notes
- Hopper Confidential Compute early access features are supported on NVIDIA Driver Version `550` and later only
- Release Notes may be found [here](https://docs.nvidia.com/confidential-computing/#release-notes).

## License

This repository is licensed under Apache License v2.0 except where otherwise noted.