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

# Install the package again to ensure any changes in the source files are reflected
echo "Re-installing the package to ensure any changes are reflected..."
pip install .

# Copy the program to /usr/local/bin/
echo "Copying the program to /usr/local/bin/..."
cp "$SCRIPT_DIR/eagle_packets_scanner.py" /usr/local/bin/eagle_scanner
chmod +x /usr/local/bin/eagle_scanner

echo "Installation completed successfully."
