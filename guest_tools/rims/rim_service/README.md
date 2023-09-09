# NVIDIA RIM (Reference Integrity Measurements) Service

## Introduction

Reference Integrity Measurement (RIM) structures are utilized by Verifiers to authenticate actual values ("Evidence") against expected values ("Reference Values"). The NVIDIA RIM Service functions as a file-hosting REST API service designed for managing these RIM Structures.

Please note that during the Early Access Release (beta), the RIM Service enables the retrieval of vBIOS and Driver RIM files. However, for the General Availability (GA) Release, the RIM Service will be integrated with the NVIDIA Local Verifier. Keep in mind that APIs may undergo changes until the GA release.

## Usage

### GET all available GPU Driver / vBIOS RIM Ids
- URL: https://rim.attestation.nvidia.com
- HTTP Method: GET
- Resource: /v1/rim/ids
- Content-Type: Application-json
- Authorization: None

Call:
```
% curl --location 'https://rim.attestation.nvidia.com/v1/rim/ids'
```

Response:
​
```
{
    "ids": [
        "RIM_ID_1",
        "RIM_ID_2",
        ...
    ]
}
```

### GET RIM Bundle​ using the ID
- URL: https://rim.attestation.nvidia.com
- HTTP Method: GET
- Resource: /v1/rim/{id}
- Content-Type: Application-json
- Authorization: None

​
| Parameter | Value | Description |
|-----------|-------|-------------|
| id | <rim_id> | The ID of the RIM file of interest.|


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
- Integration with NVIDIA Local GPU Verifier
- NVIDIA Remote Attestation Service (NRAS) integration
