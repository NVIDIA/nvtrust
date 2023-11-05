# Verifier

The Verifier is a Python-based tool that validates GPU measurements by comparing an authenticated attestation report containing runtime measurements with authenticated golden measurements. Its purpose is to verify if the software and hardware state of the GPU are in accordance with the intended state.

NOTE: Version 1.0.0 is currently in the Early Access Release (beta) stage, and please note that the APIs are subject to change until the General Availability (GA) release.

NOTE: In order to use the Verifier tool, please make sure that the confidential compute (CC) is enabled in the system.

## Install

### Create a new Python Virtual Env [Optional] 

    python3 -m venv  ./prodtest
    source ./prodtest/bin/activate

### Install and run Local GPU Verifier as a root user

If the user wants to run the verifier to set the GPU Ready State based on the Attestation results, they will need to install and execute the tool with administrative privileges (e.g., as a superuser or using root privileges).

    cd local_gpu_verifier
    sudo pip3 install .
    sudo python3 -m verifier.cc_admin

Note: If you encounter issues while building the package, please execute the following commands to update to the latest versions of setuptools and pip:

     sudo python3 -m pip install --upgrade setuptools
     sudo pip install -U pip

### Install and run Local GPU Verifier as a non-root user

For use cases where the user does not intend to set the GPU Ready State (e.g., when using the Attestation SDK), you can install and run the Verifier tool without requiring sudo privileges.

    cd local_gpu_verifier
    pip3 install .
    python3 -m verifier.cc_admin

If you encounter any permission issues while building the package, please execute the following commands and then build the package again

    cd local_gpu_verifier
    rm -r build

If you encounter any pip related issues while building the package, please execute the following commands to update to the latest versions of setuptools and pip

     python3 -m pip install --upgrade setuptools
     pip install -U pip


## Usage
To run the cc_admin module, use the following command:

    python3 -m verifier.cc_admin [-h] [-v] [--test_no_gpu] [--driver_rim DRIVER_RIM] [--vbios_rim VBIOS_RIM] [--user_mode] [--nonce] [--allow_hold_cert]

    options:
      -h, --help            show this help message and exit
      -v, --verbose         Print more detailed output.
      --test_no_gpu         If there is no gpu and we need to test the verifier, then no nvml apis will be available so, the verifier will use a hardcoded gpu info.
      --driver_rim DRIVER_RIM
                            The path to the driver RIM. If not provided, it will use the default file : "/usr/share/nvidia/rim/RIM_GH100PROD.swidtag"
      --vbios_rim VBIOS_RIM
                            The path to the VBIOS RIM. If not provided, it will try to find the appropriate file in verifier_cc/samples/ directory for the VBIOS ROM flashed onto the GPU.
      --user_mode           Runs the gpu attestation in user mode.
      --allow_hold_cert     If the user wants to continue the attestation in case of the OCSP revocation status of the certificate in the RIM files is 'certificate_hold'
      --nonce               Specify a Nonce for Attestation Report
      --rim_root_cert RIM_ROOT_CERT 
                            The absolute path to the root certificate to be used for verifying the certificate chain of the driver and vBIOS RIM certificate chain
      --rim_service_url RIM_SERVICE_URL 
                            The URL to be used for fetching driver and vBIOS RIM files. eg: https://rim.nvidia.com/rims/

If you need information about any function, use
        
    help(function_name)

For example:

    e.g. help(verify_measurement_signature)


## Module details:
### rim 
RIM is reference integrity manifest containing golden measurements for GPU. You can find the TCG RIM Spec at the following link 
The RIM module performs the parsing and schema validation of the base RIM against the swidtag schema and xml signature schema. Then performs the signature verification
of the base RIM.

The RIM (Reference Integrity Manifest) is a manifest containing golden measurements for the GPU. You can find the TCG RIM Spec at the following link: [TCG RIM Spec](https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1p01_r0p16_pub.pdf). The RIM module performs the parsing and schema validation of the base RIM against the SWID tag schema and XML signature schema. It then performs the signature verification of the base RIM.



### attestation
The Attestation module is capable of extracting the measurements and the measurement signature. It then performs signature verification. DMTF's SPDM 1.1 MEASUREMENT response message is used as the attestation report for APM. You can find the SPDM 1.1 specification at the following link: [SPDM 1.1 Specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf).

### nvmlHandler
The nvmlHandler module utilizes the NVML API calls to retrieve GPU information, including the driver version, GPU certificates, attestation report, and more.

### verifier
The verifier module utilizes the RIM (Runtime Integrity Measurement) attestation module for parsing the attestation report and performing a runtime comparison of the measurements in the attestation report against the golden measurements stored in RIM.

### cc_admin
The cc_admin module retrieves the GPU information, attestation report, and the driver RIM associated with the driver version. It then proceeds with the authentication of the driver RIM and the attestation report. Afterward, it executes the verifier tool to compare the runtime measurements in the attestation report with the golden measurements stored in the driver RIM.

