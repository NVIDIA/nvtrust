# NSCQ Attestation APIs

The header files in this folder expose attestation capabilities for
the NVLink Switch through the NSCQ library.

- [nscq_attestion.h](nscq_attestation.h): Core NSCQ operations required for attestation
- [nscq_attestion_path.h](nscq_attestation_path.h): NSCQ query paths required for attestation

An example of how to use these APIs through Python bindings in [pynscq.py](pynscq.py) 
can be found in [\_\_init\_\_.py](__init__.py).

To utilize the NSCQ attestation APIs, `libnvidia-nscq` must be installed on your system.
Please see the [Driver Installation Guide - NVSwitch](https://docs.nvidia.com/datacenter/tesla/driver-installation-guide/index.html#nvswitch)
to install `libnvidia-nscq` and related packages.
