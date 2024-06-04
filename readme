# Network Decoding Program for CSN6224 – Network Security Lab 4 Exercise

## Overview
This program is a part of the CSN6224 – Network Security Lab 4 Exercise. It reads a PCAP file (`abc.pcap`), filters packets to identify those with both source and destination IP addresses belonging to Class B IPv4 address space, and writes these filtered packets to a new PCAP file (`xyz.pcap`). The program is written in C++ and includes necessary structures and functions to handle packet headers, Ethernet frames, and IP address classification.

## Files
- `main.cpp`: Contains the main source code of the program.
- `abc.pcap`: Input PCAP file with captured network packets.
- `xyz.pcap`: Output PCAP file with filtered packets.

## Usage
1. **Compilation**: Ensure you have a C++ compiler installed and run the following command to compile the program:
    ```bash
    g++ net1.cpp -o net1 -lws2_32
    ```
2. **Execution**: Run the compiled executable:
    ```bash
    ./net1
    ```
    This will read the input file `abc.pcap`, filter the packets, and write the output to `xyz.pcap`.

## Notes
- Ensure the input file `abc.pcap` is available in the working directory.
- The program is designed to run on Windows due to the use of Winsock2. For Unix-like systems, modifications are required to handle sockets differently.

## About CSN6224 – Network Security Lab 4 Exercise
This program is a part of the CSN6224 – Network Security Lab 4 Exercise. The exercise focuses on understanding network packet structures and how to decode them for security analysis. This program specifically filters packets based on IP address classes, providing a practical example of network traffic analysis.
