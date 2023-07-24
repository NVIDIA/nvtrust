# NVIDIA Attestation SDK

The Attestation SDK provides developers with a easy to use APIs for implementing attestation capabilities into their Python applications. With this SDK, you can easily integrate secure and reliable attestation services into your software, ensuring the authenticity, integrity, and trustworthiness of your system.

## Features

Local GPU Attestation (using NVIDIA NVML based Python libraries)
Note: SDK v1.0 is still in Early Access Release (beta) and APIs are subject to change until the GA release.

## Install Attestation SDK

### Pre-requisites

1. Create a Confidential Virtual Machine with the following specifications:
   - NVIDIA Hopper H100 GPU
   - r535 version of the Driver installed.
   - Make sure the SKU is supported for Confidential Computing.
2. Follow the nvTrust/guest_tools/local_gpu_verifier/README.md to install the NVIDIA GPU Local Verifier Python SDK.
3. Run the following command and ensure that you have the 'verifier' Python module installed.
    ```
    pip list | grep verifier
    verifier               1.0.0
    ```

### Install the Attestation SDK using the Wheel file

- Download the latest Wheel file from the attestation_sdk/dist directory.

- Install SDK in a python virtual environment. Please make sure that you are using the same virtual environment that you used in Step 2 for the NVIDIA Local GPU verifier scripts.

        pip3 install ./nv_attestation_sdk-<-version->-py3-none-any.whl

### Install the Attestation SDK using the source code

If you choose to install the Attestation SDK from the source code instead of a Wheel file, use the following commands:

    cd attestation_sdk
    pip3 install .

## Usage

    from nv_attestation_sdk import attestation

    # Create a Attestation object
    client = attestation.Attestation("test_node")
    
    # Add the type of verifier that you would like to use
    client.add_verifier(attestation.Devices.GPU, attestation.Environment.LOCAL, "", "")
    
    # Set the Attestation Policy that you want to validate your token against.
    #for pull policy details, please see tests/NVGPUPolicyExample.json
    attestation_results_policy = '{"version":"1.0","authorization-rules":{"x-nv-gpu-available":true,' \
                             '"x-nv-gpu-attestation-report-available":true}}'
    
    # Run Attest    
    print(client.attest())
    
    # Call validate_token to validate the results against the Appraisal policy for Attestation Results
    print(client.validate_token(attestation_results_policy))

## Running the tests

    python3 ./tests/SmallGPUTest.py

## Build

    python3 -m pip install --upgrade build
    python3 -m build

## APIs

| API                                                                                                                             | Description                                                                                                     |
|---------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Attestation(<-name->)                                                                                                           | Create a new Attestation Object used to call other Attestation methods.                                         |
| set_name(<-name->)                                                                                                              | Set a name for the Attestation SDK client                                                                       |
| add_verifier(<-attestation-device-type->, <-local/remote->, <-remote-attestation-service-url->, <-attestation-results-policy->) | Add a specific type of verifier for the client object. The verifier will be invoked during the attest operation |
| attest()                                                                                                                        | Trigger the Attestation for client object, This uses the Attestation type configured in add_verifier method     |
| validate_token(<-attestation-results-policy->)                                                                                  | Validate the Attestation Claims against a policy                                                                |

## Version Info

SDK latest version - 1.0.0

## Future Roadmap

The following are some exciting features and improvements that we plan to implement in upcoming releases of Attestation SDK. Please note that these roadmap items are subject to change based on user feedback and evolving priorities. We are committed to continuously improving our project to meet the needs of our users.

1. NVIDIA Remote Attestation Service integration.
2. More flexible Attestation result policies.
3. Other Attestation types like CPU, DPU etc.
