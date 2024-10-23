#!/bin/bash

# Check if Python is installed
if not type -P python3 >/dev/null 2>&1 && echo Python 3 is installed; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Function to remove existing virtual environment
if [ -d venv ]; then
  rm -r venv
fi

# Cd into the root of repository
cd ../../ppcie-verifier || exit

# Creating a virtual enviornment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
cd ../gpu_verifiers/local_gpu_verifier
pip3 install .
cd ../../attestation_sdk
pip3 install .
cd ../ppcie-verifier
pip3 install .