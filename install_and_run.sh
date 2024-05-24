#!/bin/bash

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Install the package
echo "Installing the package..."
python setup.py install

# Run the program
echo "Running the Eagle Packets Scanner..."
sudo eagle_scanner
