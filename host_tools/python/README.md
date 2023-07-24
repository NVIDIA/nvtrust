# NVIDIA Confidential Computing Mode Toggle Utility

This utility is used to configure the Confidential Computing modes of supported GPUs. It is designed to be run from the Host OS as a priveleged Python3 command; running it from within the Guest OS is not supported.

Supported CC modes are:

- on
  - All supported GPU security features are enabled (e.g., bus encryption, performance counters off)
- devtools
  - All supported GPU security features are enabled, however blocks preventing DevTools profiling/debugging are lifted
- off
  - The GPU operates in its default mode; no supplementary confidential computing features are enabled

## Prerequesites:
  ```bash
  sudo apt install patchelf python3-pip
  ```
## Most Commonly Used Examples
##### Query the CC mode of all H100s in the system
` sudo python3 ./gpu_cc_tool.py --gpu-name=H100 --query-cc-mode`
##### Enable CC-On mode of all H100s in the system
` sudo python3 ./gpu_cc_tool.py --gpu-name=H100 --set-cc-mode=on --reset-after-cc-mode-switch `
##### Disable CC mode on a specific H100 in the system
` sudo python3 ./gpu_cc_tool.py --gpu-bdf=45:00.0 --set-cc-mode=off --reset-after-cc-mode-switch`

## Usage
  ```bash
  sudo python3 gpu_cc_tool.py --help

NVIDIA GPU Tools version %VERSION%
Usage: gpu_cc_tool.py [options]

Options:
  -h, --help            show this help message and exit
  --gpu=GPU
  --gpu-bdf=GPU_BDF     Select a single GPU by providing a substring of the
                        BDF, e.g. '01:00'.
  --gpu-name=GPU_NAME   Select a single GPU by providing a substring of the
                        GPU name, e.g. 'T4'. If multiple GPUs match, the first
                        one will be used.
  --no-gpu              Do not use any of the GPUs; commands requiring one
                        will not work.
  --log=LOG
  --reset-with-os       Reset with OS through /sys/.../reset
  --query-cc-mode       Query the current Confidential Computing (CC) mode of
                        the GPU.
  --query-cc-settings   Query the Confidential Computing (CC) settings of the
                        GPU.This prints the lower level setting knobs that
                        will take effect upon GPU reset.
  --set-cc-mode=SET_CC_MODE
                        Configure Confidentail Computing (CC) mode. The
                        choices are off (disabled), on (enabled) or devtools
                        (enabled in DevTools mode).The GPU needs to be reset
                        to make the selected mode active. See --reset-after-
                        cc-mode-switch for one way of doing it.
  --reset-after-cc-mode-switch
                        Reset the GPU after switching CC mode such that it is
                        activated immediately.
```
## Modes
