# NVIDIA Attestation SDK

The Attestation SDK offers developers easy-to-use APIs for implementing attestation capabilities into their Python applications. With this SDK, you can seamlessly integrate secure and reliable attestation services into your software, thereby ensuring the authenticity, integrity, and trustworthiness of your system.

- [NVIDIA Attestation SDK](#nvidia-attestation-sdk)
  - [Features](#features)
  - [Install Attestation SDK](#install-attestation-sdk)
    - [From Source](#from-source)
    - [From PyPI](#from-pypi)
    - [Troubleshooting Installation Issues](#troubleshooting-installation-issues)
  - [GPU Attestation](#gpu-attestation)
    - [Pre-requisites](#pre-requisites)
    - [How to do Attestation](#how-to-do-attestation)
  - [Switch Attestation](#switch-attestation)
    - [Pre-requisites](#pre-requisites-1)
    - [How to do Attestation](#how-to-do-attestation-1)
  - [Claims and Troubleshooting information](#claims-and-troubleshooting-information)
  - [Policy File](#policy-file)
  - [Building Attestation SDK](#building-attestation-sdk)
  - [Compatibility Matrix](#compatibility-matrix)
  - [Attestation SDK APIs](#attestation-sdk-apis)
  - [Attestation SDK configuration](#attestation-sdk-configuration)
  - [Note](#note)

## Features

- Local GPU Attestation (using NVIDIA NVML based Python libraries)
- Remote GPU Attestation (using NVIDIA Remote Attestation Service)
- Local Switch Attestation (using NVIDIA NSCQ based Python libraries)
- Remote Switch Attestation (using NVIDIA Remote Attestation Service)

## Install Attestation SDK

Before installation, please review the [Compatibility Matrix](#compatibility-matrix) to determine the correct version of nvTrust and driver to install.

### From Source

If you choose to install the Attestation SDK from the source code, use the following commands:

    cd attestation_sdk
    pip3 install .

### From PyPI

If you choose to install the Attestation SDK directly from PyPI, use the following commands (requires virtual environment creation):

    python3 -m venv venv
    source venv/bin/activate
    pip3 install nv-attestation-sdk

### Troubleshooting Installation Issues

If you encounter warning and installation issues similar to the below while installing the package:
`WARNING: Ignoring invalid distribution ~v-attestation-sdk <site-package-directory>`
     
Please execute the following commands to clean up packages that were not installed properly and then re-try the installation:
         
         rm -rf $(ls -l <site-packages-directory> | grep '~' | awk '{print $9}')

## GPU Attestation

### Pre-requisites

1. Create a Confidential Virtual Machine with the following specifications:
      - NVIDIA Hopper H100 (or later) GPU that supports CC
      - NVIDIA GPU Driver with CC / PPCIE support.
      - GPU SKU that supports Confidential Computing.

2. Install Python 3.8 or later.

3. Follow the instructions in nvTrust/guest_tools/local_gpu_verifier/README.md to install the NVIDIA GPU Local Verifier Python SDK. (Required for source code installation only) 
   
4. Run the following command and ensure that you have the 'nv-local-gpu-verifier' Python module installed.
    ```
    pip list | grep nv-local-gpu-verifier
    nv-local-gpu-verifier               1.5.0
    ```

### How to do Attestation

- Local GPU Attestation

  Refer to the [sample implementation](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/tests/end_to_end/hardware/LocalGPUTest.py)

- Remote GPU Attestation

  Refer to the [sample implementation](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/tests/end_to_end/hardware/RemoteGPUTest.py)

## Switch Attestation

### Pre-requisites

1. Create a Confidential Virtual Machine with multiple GPUs connected by nvSwitch with the following specifications:
      - LS10 Switch supporting PPCIE mode
      - NvSwitch Driver with PPCIE support.
      - GPU SKU that supports Confidential Computing.

2. Unlike GPU Verifier, Switch Verifier comes pre-installed with Attestation SDK.

### How to do Attestation

- Local nvSwitch Attestation

  Refer to the [sample implementation](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/tests/end_to_end/hardware/LocalSwitchTest.py)

- Remote nvSwitch Attestation

  Refer to the [sample implementation](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/tests/end_to_end/hardware/RemoteSwitchTest.py)

## Claims and Troubleshooting information

For local and remote verifier claims information for NVIDIA GPUs, switches, and related troubleshooting information, please refer to the [Attestation Troubleshooting documentation](../attestation_troubleshooting_guide.md).

## Policy File

You can find a sample Attestation Result policy file for Local and Remote Attestation [here](tests/policies/).
Please note that the Schema/EAT claim information is subject to change in future releases.

## Building Attestation SDK

    python3 -m pip install --upgrade build
    python3 -m build

## Compatibility Matrix 

SDK version     | NRAS API Version | Claims Version
--------------- |-----------------|----------------
v1.1.0          | v1              | N/A
v1.2.0          | v1              | N/A
v1.3.0          | v1              | N/A
v1.4.0          | v1              | N/A
v1.5.0          | v2              | N/A
v2.0.0          | v3              | 2.0
v2.1.0          | v3              | 2.0
v2.1.1          | v3              | 2.0
v2.1.2          | v3              | 2.0
v2.1.3          | v3              | 2.0
v2.3.0          | v3              | 2.0

More information on claims can be found [here](https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_troubleshooting_guide.md)

## Attestation SDK APIs

**nv_attestation_sdk import attestation**
| API                                                                                                                             | Description                                                                                                                           |
|---------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| Attestation(<-name->)                                                                                                           | Create a new Attestation Object used to call other Attestation methods.                                                               |
| set_name(<-name->)                                                                                                              | Set a name for the Attestation SDK client                                                                                             |
| set_nonce(<-nonce->)                                                                                                            | Set a nonce for Attestation                                                                                                           |
| set_ocsp_nonce_disabled(<-bool->)                                                                                               | Flag which indicates whether to include a nonce when calling OCSP. Only applicable for local GPU attestation. False by default        |
| add_verifier(<-attestation-device-type->, <-local/remote->, <-remote-attestation-service-url->, <-attestation-results-policy->) | Add a specific type of verifier for the client object. The verifier will be invoked during the attest operation                       |
| get_verifiers()                                                                                                                 | Retrieves the list of verifiers added to the client object.                                                                              |
| get_evidence()                                                                                                                  | Retrieves the list of evidence based on the attestation device (e.g., GPU, switch) and the type of attestation (e.g., local, remote). |
| attest()                                                                                                                        | Trigger the Attestation for the client object, This uses the Attestation type configured in the add_verifier method                           |
| get_token()                                                                                                                     | Retrieves the Attestation token that contains claims corresponding to the Attestation result.                                             |
| get_ocsp_nonce_disabled()                                                                                                       | Retrieves the flag which indicates whether a nonce is included when calling OCSP.                                                     |
| validate_token(<-attestation-results-policy->)                                                                                  | Validate the Attestation Claims against a policy                                                                                      |
| decode_token(<-jwt-token->)                                                                                                     | Decodes the JWT token to claims received by the verifier                                                                              |
## Attestation SDK configuration
The below configuration can be set using environment variables in the console
Configuration            | Values           |                                   Explanation                                                                                  |
-------------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------
NV_ALLOW_HOLD_CERT       | true/false       | Enable attestation if the OCSP revocation status of the certificate in the RIM files is 'certificate_hold'. Defaults to false.'|

## Note
Please note that starting from nvTrust v1.5.0, the NRAS v1 API and Relying Party Policy version 1.0 have been deprecated. Additionally, installation via wheel files will no longer be supported from v1.5.0 onward.