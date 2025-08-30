PortScanner & OS Detector
This project is a powerful, multi-functional network discovery and security auditing tool developed using C++ and the Winsock library. It uses low-level raw sockets to gather in-depth information about target systems on a network.

Key Features
Multithreaded Port Scanning: Rapidly scans for open TCP and UDP ports on a specified IP address.

Service and OS Fingerprinting: Analyzes unique characteristics of incoming network packets, such as TTL (Time to Live), TCP Window Size, and TCP Options, to accurately determine the target system's operating system.

Low-Level Network Access: Capable of directly crafting and reading TCP and IP packet headers, allowing for byte-level manipulation and analysis of network traffic.

Technologies Used
C++: Chosen for its high performance and ability to perform low-level system access.

Winsock (Windows Sockets 2): The core library for network programming on the Windows operating system.

Raw Sockets: Utilized to create and send custom TCP/IP packets, a feature that requires administrator privileges.

Legal and Ethical Disclaimer
This tool is developed for educational and research purposes only. The developer assumes no liability for any misuse or illegal activities performed with this tool.

Administrator Privileges: The program requires administrator privileges to function due to its use of raw sockets.

Legal Notice: Unauthorized scanning of a network is illegal in most countries. Please ensure you have explicit legal permission to use this tool on any network other than your own.

Ethical Use: Remember that network security tools can be dangerous in the wrong hands. Use this tool responsibly and ethically.

The user is solely responsible for any consequences that arise from the use of this software.

How to Compile and Run
Prerequisites:

Visual Studio 2019 or newer.

The "Desktop development with C++" workload.

Compilation:

Open the project folder in Visual Studio.

Go to the "Build" menu and build the project.

Execution:

Open Command Prompt as an administrator.

Navigate to the directory containing the compiled .exe file.

Run the program using the format PortScanner.exe <IP_Address>. For example:

PortScanner.exe 192.168.1.1
Contributing
If you wish to contribute, feel free to open a "pull request" or an "issue."
