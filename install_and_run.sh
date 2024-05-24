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

# Copy the program to the system path
echo "Copying the program to the system path..."
sudo cp "$SCRIPT_DIR/eagle_packets_scanner.py" /usr/local/bin/eagle_scanner
sudo chmod +x /usr/local/bin/eagle_scanner

# Run the program
echo "Running the Eagle Packets Scanner..."
eagle_scanner
