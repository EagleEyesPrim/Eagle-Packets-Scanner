#!/bin/bash

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Install the package
echo "Installing the package..."
python setup.py install

# Get the file folder using environment variables
SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

# Move the program file to an easily accessible folder
sudo cp "$SCRIPT_DIR/eagle_scanner" /usr/local/bin

# Run the program
echo "Running the Eagle Packets Scanner..."
sudo eagle_scanner
