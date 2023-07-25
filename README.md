# nvTrust: NVIDIA Confidential Computing Ancillary Software

nvTrust is a repository which contains much of the utilities & tools, open-source code, and SDKs leveraged when using NVIDIA solutions in trusted environements, such as Confidential Computing.

For more information, including documentation, whitepapers, and videos regarding the Hopper Confidential Computing story, please visit [docs.nvidia.com/confidential-computing/index.html]()

## Early Access Considerations
This branch of nvTrust is currently considered 
`Early Access`. 

This early-access software release features a software stack targeting a single H100 GPU in passthrough mode with a single session key for encryption and authentication and basic use of the Developer Tools. 

Code and data will be confidential up to the limits of the NIST SP800-38D AES-GCM standard, after which the VM should be restarted, which causes a fresh session key to be created.

**NVIDIA recommends users invoke good practices while utilizing the early-access by testing only with synthetic data and non-proprietary AI models.**

## Release Notes
- Hopper Confidential Compute early access features are supported on NVIDIA Driver Version `535.86` and later only
- Release Notes may be found [here](https://docs.nvidia.com/confidential-computing/#release-notes).

## License
The license for this repository is Apache v2 except where otherwise noted.
## Folder Sructure
- **docs** - Collateral relating to Confidential Computing with NVIDIA GPUs
    - Release Notes
    - Deployment Guide (Walkthrough)
    - Hopper Confidential Computing Whitepaper
    - Local Verifier Application User Guide
- **guest_tools** - Contains utilities specific to running _within_ a Confidential VM
    - Attestation SDK
    - Local Attestation Verifiers
    - RIM Acquisition Service
- **host_tools** - Contains utilities specific to configuring the GPU's Confidential Computing Modes, as well as sample scripts to create and run a Confidential VM from within the _host_
    - GPU CC Mode Setting scripts
    - KVM Sample Scripts for launching a CVM
    - Staging folders for Deployment Guide found under docs/
- **infrastructure** - Contains the open source, third-party code that was used for validation of our Hopper Confidential Computing Solutions
    - KVM source code, including OVMF and QEMU
    - Linux source code, along with appropriate GPU-specific patches
    - Pointers to original GitHub sources.
