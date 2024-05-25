# Eagle Packets Scanner

Eagle Packets Scanner (EPS) is a comprehensive tool designed for real-time network packet analysis and protocol inspection. Built with Python, it leverages powerful libraries such as Scapy for packet capture and IPWhois for IP reputation checking. This tool is essential for network administrators, security professionals, and anyone interested in monitoring and analyzing network traffic.

EPS captures packets from network interfaces, analyzes them to determine source and destination IP addresses, and checks the reputation of these IPs. The tool supports a wide range of network protocols, including TCP, UDP, HTTP, HTTPS, and more, providing detailed insights into network communications.

One of the standout features of EPS is its terminal-based graphical user interface, implemented using the Blessed library. This interface presents real-time data in a clear, color-coded, and dynamically updating table, making it easy to monitor network activity.

EPS is designed to be user-friendly and accessible. Installation is straightforward, with a simple setup process that includes installing required Python libraries and running the script. The tool is cross-platform, with instructions provided for both Linux and Windows systems.

In summary, Eagle Packets Scanner is a versatile and powerful network analysis tool that offers detailed insights into network traffic, making it an invaluable resource for maintaining network security and performance.

## Features

- Real-time network packet capture and analysis.
- IP address reputation checking using IPWhois.
- Support for a wide range of protocols.
- Organized and continuously updated data display in a table.
- Terminal-based graphical user interface using the Blessed library.

## Requirements

- Python 3.6 or later.
- Required Python libraries: psutil, scapy, ipwhois, blessed, termcolor, tabulate.

## Installation

### Linux

1. **Install basic requirements:**

   Ensure you have Python 3 installed on your system. You can install Python 3 using the appropriate package manager for your system:

   ```sh
   sudo apt update
   sudo apt install python3 python3-pip
   ```

2. **Clone the repository:**

   Clone this repository to your local machine:

   ```sh
   git clone https://github.com/EagleEyesPrim/Eagle-Packets-Scanner.git
   cd Eagle_Packets_Scanner
   ```

3. **Install the requirements:**

   Install the required libraries using pip:

   ```sh
   pip3 install -r requirements.txt
   ```

4. **Make the script executable:**

   ```sh
   chmod +x eagle_packets_scanner.py
   ```

5. **Move the script to an accessible directory:**

   ```sh
   sudo mv eagle_packets_scanner.py /usr/local/bin/eagle_packets_scanner
   ```

6. **Run the program:**

   Now you can run the program from any terminal using the command:

   ```sh
   eagle_packets_scanner
   ```

### Windows

1. **Install Python:**

   Download and install Python 3 from [python.org](https://www.python.org/).

2. **Clone the repository:**

   Clone this repository to your local machine using Git Bash or any other tool:

   ```sh
   git clone https://github.com/YourUsername/eagle_packets_scanner.git
   cd eagle_packets_scanner
   ```

3. **Install the requirements:**

   Install the required libraries using pip:

   ```sh
   pip install -r requirements.txt
   ```

4. **Run the program:**

   You can run the program using the following command in PowerShell or CMD:

   ```sh
   python eagle_packets_scanner.py
   ```

## Usage

Once the program is running, a terminal-based graphical user interface will display network traffic and protocol analysis. The table will be continuously updated to reflect the latest captured data. Ensure that you use this tool within the bounds of the law.

## License

Eagle Packets Scanner is distributed under the MIT License. See the `LICENSE` file for more information.


## Note: The program will be continuously developed with additional features to enhance user performance
