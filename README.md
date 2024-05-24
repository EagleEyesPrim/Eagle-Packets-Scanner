# Eagle Packets Scanner

## Introduction
Eagle Packets Scanner is a network packet analysis tool designed to monitor and analyze packets sent and received on the internet connection of the client's device. The tool examines the source and destination IP addresses and determines whether they are trustworthy or suspicious using WHOIS queries.

#### Purpose of Using the Tool
- **Network Monitoring**: Assist users in analyzing network packets passing through their network.
- **Security Analysis**: Identify the reputation of IP addresses and examine them to determine if they are trustworthy.
- **Network Diagnostics**: Utilize the tool as part of diagnosing network issues.

## Installation Steps
#### 1-Installing the Program on Linux:

1. **Download the Program**:
   Download the project containing the following files:
   - `eagle_packets_scanner.py`
   - `requirements.txt`
   - `setup.py`
   - `install_and_run.sh`
  
   ```bash
   sudo git clone https://github.com/EagleEyesPrim/Eagle-Packets-Scanner.git
   ```

2. **Set Up Environment**:
   Ensure you have Python installed on your system. You can check this by running the following command in the terminal:
   ```bash
   python --version
   ```

3. **Make the Shell Script Executable**:
   Before running the shell script, the file needs to be made executable. Open the terminal, navigate to the project directory, then execute the following command:
   ```bash
   chmod +x install_and_run.sh
   ```

4. **Run the Shell Script**:
   Execute the shell script to install the requirements and run the program:
   ```bash
   ./install_and_run.sh
   ```

   This script will perform the following steps:
   - Install the required libraries listed in `requirements.txt`.
   - Install the package using `setup.py`.
   - Run the Eagle Packets Scanner program with administrator privileges.

#### Running the Program

After installation, you can run the program from anywhere in the terminal using the following command:
```bash
sudo eagle_scanner
```

#### 2-Installing the Program on Windows:
   - Download Eagle Packets Scanner project from GitHub.
   - Navigate to the project directory in the command prompt.
   - Run the following command to install requirements:
     ```bash
     pip install -r requirements.txt
     ```
   - After installation, run the program using the command:
     ```bash
     python eagle_packets_scanner.py
     ```

## Program Functionality

- **Packet Analysis**:
  - The program monitors all packets passing through your network interface.
  - For each captured packet, it extracts the source and destination IP addresses.

- **Checking IP Reputation**:
  - The program utilizes the `ipwhois` library for WHOIS queries to determine the reputation of IP addresses.
  - If the query results contain entities, the IP address is considered trustworthy; otherwise, it is flagged as suspicious.
  - Private or reserved IP addresses are handled as a special case.

- **Displaying Results**:
  - The source and destination IP addresses for each packet are displayed along with their status (trusted or suspicious).

## Notes
- **Permissions**: The program must be run with administrator (root) privileges to analyze network packets.
- **Security**: Ensure that you use the tool on your own network and with the consent of the network administrator to comply with security and privacy policies.

With these steps, you can easily install and use the Eagle Packets Scanner tool to analyze and monitor data traffic on your network.
