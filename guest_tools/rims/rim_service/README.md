# NVIDIA RIM (Reference Integrity Measurements) Service

## Introduction

Reference Integrity Measurement (RIM) structures are utilized by Verifiers to authenticate actual values ("Evidence") against expected values ("Reference Values"). The NVIDIA RIM Service functions as a file-hosting REST API service designed for managing these RIM Structures.

Please note that during the Early Access Release (beta), the RIM Service enables the retrieval of vBIOS and Driver RIM files. However, for the General Availability (GA) Release, the RIM Service will be integrated with the NVIDIA Local Verifier. Keep in mind that APIs may undergo changes until the GA release.

## Latest RIM file IDs

### Driver RIM IDs

NV_GPU_DRIVER_GH100_535.89

NV_GPU_DRIVER_GH100_545

### Driver RIM IDs

NV_GPU_VBIOS_1010_0200_882_96005E0001

NV_GPU_VBIOS_1010_0205_862_96005E0002
​
## Usage

### GET RIM Bundle​
- URL: https://rim.attestation.nvidia.com
- HTTP Method: GET
- Resource: /v1/rim/{id}
- Content-Type: Application-json
- Authorization: None

​
| Parameter | Value | Description |
|-----------|-------|-------------|
| id | <rim_id> | The ID of the RIM file of interest.|
​
​

Call:
```
% curl --location 'https://rim.attestation.nvidia.com/v1/rim/<id>'
```
​
Response:
​
```
{
    "id": "<id>",
    "rim": base64("<rim_base64_format>")
}
```
​
Decode:

pre-requisite: [Install jq](https://jqlang.github.io/jq/download/)
​
```
% curl -s 'https://rim.attestation.nvidia.com/v1/rim/<id>' | jq -r '.rim' | base64 -D -o output.xml
```
​
## Future Roadmap
​
The following are some exciting features and improvements that we plan to implement in upcoming releases of RIM Service. Please note that these roadmap items are subject to change based on user feedback and evolving priorities. We are committed to continuously improving our project to meet the needs of our users.
​
- RIM Service will later be integrated with the NVIDIA Local GPU Verifier, to serve the RIM file used for Attestation.