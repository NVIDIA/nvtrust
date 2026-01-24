#!/bin/bash

# Check if Python is installed
if not type -P python3 >/dev/null 2>&1 && echo Python 3 is installed; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Check if nvattest CLI is installed
NVATTEST_MISSING=false
if ! command -v nvattest >/dev/null 2>&1; then
    NVATTEST_MISSING=true
    echo "WARNING: NVIDIA Attestation CLI (nvattest) is not installed or not on your PATH."
    echo "The PPCIE Verifier requires nvattest to be installed."
    echo ""
    echo "Continuing with PPCIE Verifier installation, but it will not work without nvattest..."
    echo ""
fi

# Function to remove existing virtual environment
if [ -d venv ]; then
  rm -r venv
fi

# Cd into the root of repository
cd ../../ppcie-verifier-sdk-cpp || exit

# Creating a virtual enviornment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
cd ../ppcie-verifier-sdk-cpp
pip3 install .

if [ "$NVATTEST_MISSING" = true ]; then
    echo ""
    echo "WARNING: NVIDIA Attestation CLI (nvattest) is not installed!"
    echo ""
    echo "The PPCIE Verifier requires nvattest to be installed."
    echo ""
    echo "To install nvattest, follow the NVIDIA Attestation CLI documentation: https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html"
    echo "After installation, verify with: nvattest version"
    echo ""
fi