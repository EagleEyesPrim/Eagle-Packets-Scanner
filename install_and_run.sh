#!/bin/bash

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Install the package
echo "Installing the package..."
python setup.py install

# Move the program file to an easily accessible folder
sudo cp /path/to/eagle_scanner /usr/local/bin

# Create a symbolic link to the playable file in a folder that is included in PATH
sudo ln -s /usr/local/bin/eagle_scanner /usr/bin/eagle_scanner

# Run the program
echo "Running the Eagle Packets Scanner..."
sudo eagle_scanner
