# NVIDIA Attestation SDK

The Attestation SDK offers developers easy-to-use APIs for implementing attestation capabilities into their Python applications. With this SDK, you can seamlessly integrate secure and reliable attestation services into your software, thereby ensuring the authenticity, integrity, and trustworthiness of your system.

- [NVIDIA Attestation SDK](#nvidia-attestation-sdk)
  - [Features](#features)
  - [Install Attestation SDK](#install-attestation-sdk)
    - [From Wheel file](#from-wheel-file)
    - [From Source](#from-source)
  - [GPU Attestation](#gpu-attestation)
    - [Pre-requisites](#pre-requisites)
    - [Local GPU Attestation](#local-gpu-attestation)
      - [Policy File](#policy-file)
      - [How to do Perform Attestation](#how-to-do-perform-attestation)
    - [Remote GPU Attestation](#remote-gpu-attestation)
      - [Pre-Requisites](#pre-requisites-1)
      - [Policy File](#policy-file-1)
      - [How to do Perform Attestation](#how-to-do-perform-attestation-1)
  - [Building Attestation SDK](#building-attestation-sdk)
  - [APIs](#apis)
  - [End-User License Agreement](#end-user-license-agreement)


## Features

- Local GPU Attestation (using NVIDIA NVML based Python libraries)
- Remote GPU Attestation (using NVIDIA Remote Attestation Service)

Note: Attestation SDK is still in Early Access Release (beta), and the APIs may undergo changes until the GA release.

## Install Attestation SDK

### From Wheel file

- Download the latest Wheel file from the [this directory](dist/).

- Install the SDK in a Python virtual environment. Please make sure that you are using the same virtual environment that you used in Step 2 for the NVIDIA Local GPU verifier scripts.

        pip3 install ./nv_attestation_sdk-<-version->-py3-none-any.whl

### From Source

If you choose to install the Attestation SDK from the source code instead of a Wheel file, use the following commands:

    cd attestation_sdk
    pip3 install .

## GPU Attestation

### Pre-requisites

1. Create a Confidential Virtual Machine with the following specifications:
- NVIDIA Hopper H100 GPU
- Driver version r535 installed.
- Ensure that the SKU is supported for Confidential Computing.

2. Install Python 3.7 or later.

3. Follow the instructions in nvTrust/guest_tools/local_gpu_verifier/README.md to install the NVIDIA GPU Local Verifier Python SDK.
   
4. Run the following command and ensure that you have the 'verifier' Python module installed.
    ```
    pip list | grep nv-local-gpu-verifier
    nv-local-gpu-verifier              1.4.0
    ```

### Local GPU Attestation

#### Policy File

You can find a sample Attestation Result policy file for Local GPU Attestation [here](tests/NVGPULocalPolicyExample.json)
Please note that the Schema/EAT claim information is subject to change in future releases.

#### How to do Perform Attestation

Please refer to the [sample implementation](tests/LocalGPUTest.py)

### Remote GPU Attestation

#### Pre-Requisites

[NVIDIA Remote Attestation Service (NRAS)](https://nras.attestation.nvidia.com) must be accessible from the machine.

#### Policy File

You can find a sample Attestation Result policy file for Remote GPU Attestation [here](tests/NVGPURemotePolicyExample.json)

Please note that the Schema/EAT claim information is subject to change in future releases.

#### How to do Perform Attestation

Please refer to the [sample implementation](tests/RemoteGPUTest.py)

## Building Attestation SDK

    python3 -m pip install --upgrade build
    python3 -m build

## APIs

### nv_attestation_sdk import attestation
| API                                                                                                                             | Description                                                                                                     |
|---------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Attestation(<-name->)                                                                                                           | Create a new Attestation Object used to call other Attestation methods.                                         |
| set_name(<-name->)                                                                                                              | Set a name for the Attestation SDK client                                                                       |
| add_verifier(<-attestation-device-type->, <-local/remote->, <-remote-attestation-service-url->, <-attestation-results-policy->) | Add a specific type of verifier for the client object. The verifier will be invoked during the attest operation |
| attest()                                                                                                                        | Trigger the Attestation for client object, This uses the Attestation type configured in add_verifier method     |
| validate_token(<-attestation-results-policy->)                                                                                  | Validate the Attestation Claims against a policy                                                                |

### nv_attestation_sdk.gpu.attest_gpu_remote

| API                                                                                                                             | Description                                                                                                     |
|---------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| generate_evidence(<-nonce->)                                                                                                           | Generate GPU attestation evidence using the Local GPU Verifier Python SDK with a user-provided nonce.                                         |
| verify_evidence(<-nonce->, <-evidence->,<-nras_url->)                                                                                                              |Verify the evidence with the NVIDIA Remote Attestation Service (NRAS)                                                                       |

# End-user License Agreement

By using the Attestation Suite Services, you affirm that you have read the Agreement and agree to its terms. If you do not have the required authority to enter into the Agreement or if you do not accept all Agreement terms and conditions, do not use the Attestation Suite Services. Please see the [End-user License Agreement](https://docs.attestation.nvidia.com/EULA/eula.html) for more information on data collection.
