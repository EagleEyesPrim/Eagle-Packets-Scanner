#!/bin/bash

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

# Install requirements
echo "Installing requirements..."
pip install -r "$SCRIPT_DIR/requirements.txt"

# Install the package
echo "Installing the package..."
cd "$SCRIPT_DIR"  # Change directory to the script's directory
pip install .

# Run the program
echo "Running the Eagle Packets Scanner..."
python eagle_scanner
