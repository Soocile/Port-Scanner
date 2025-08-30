
#include"PORTSCANNER.hpp"
#include<iostream>
#include<thread>

//a variable which necessary for WSAStartup
static WSAData wsadata;


PortScanner::PortScanner() {

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {

		throw std::runtime_error("WSAStartup Failed");
	}
}

PortScanner::~PortScanner() {

	//clear the winsock with wsacleanup

	WSACleanup();
}


int PortScanner::getWinsockError() {

	return WSAGetLastError();
}

void PortScanner::scanWorker(const std::string& ipAddress, unsigned short startPort,
	unsigned  short endPort, ScanType type) {
	for (int port = startPort; port <= endPort; ++port) {

		if (type == TCP) {
			if (isTcpPortOpen(ipAddress, port)) {
				// it could be a problem if multithread try to write on std::cout
				// so we will use locking.
				std::string serviceInfo = getTCPServiceInfo(ipAddress, port);
				std::cout << "Port:" << port << " is open (TCP). Service: " << serviceInfo << std::endl;
			}
			
		}
		else if (type == UDP) {

			if (isUdpPortOpen(ipAddress, port)) {
				std::string serviceInfo = getUdpServiceInfo(ipAddress, port);
				std::cout << "Port:" << port << " is open (UDP). Info: " << serviceInfo << std::endl;
			}
		}
	
	}

	std::cout << "Scan Finished..." << std::endl;
}


void PortScanner::scan(const std::string& ipAddress, unsigned short startPort, unsigned short endPort, ScanType type) {

	if (type == TCP) {
		std::cout << "Started multithreaded TCP scan on" << ipAddress << "..." << std::endl;
	}
	else if (type == UDP) {
		std::cout << "Started multithreaded UDP scan on" << ipAddress << "..." << std::endl;
	}

	const int numThreads = 6;
	const int portRangePerThread = (endPort - startPort + 1) / numThreads;

	std::vector<std::thread> threads;

	for (int i = 0; i < numThreads; ++i) {

		int threadStartPort = startPort + i * portRangePerThread;
		int threadEndPort = threadStartPort + portRangePerThread - 1;

		//If the port range is not exactly divisible by the number of threads
		// (e.g. 100 ports and 6 workers), it assigns all remaining ports to the last worker,
		// ensuring that no port remains unscanned.
		if (i == numThreads - 1) {

			threadEndPort = endPort;
		}

		threads.emplace_back(&PortScanner::scanWorker, this, ipAddress, threadStartPort, threadEndPort);


		
		}
	//wait for all threads to done 
	for (auto& t : threads) {

		if (t.joinable()) {
			t.join();
		}
	}

	std::cout << "multithreaded scan finished" << std::endl;
}

bool PortScanner::isTcpPortOpen(const std::string& ipAddress, unsigned short port) {


	// create a tcp socket
	SOCKET clientSocket;

	clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (clientSocket == INVALID_SOCKET) {

		std::cerr << "failed to create socket. Error Code" << getWinsockError() << std::endl;
		return false;
	}

	//set the server addr and port

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port); // host to network shorts
	inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr.s_addr);


	//create a timeout
	DWORD timeout = 500;

	setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
		sizeof(timeout));

	setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout),
		sizeof(timeout));


	//try to connect

	if (connect(clientSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {

		closesocket(clientSocket);
		int error = getWinsockError();

		//10061 --> connection refused error, 10060 --> timeout error (those errors shows us that the port is close);

		if (error == 10061 || error == 10060) {
			return false;
		}
		else {
			//other errors...
			std::cout <<"other errors"<< getWinsockError() << std::endl;
			return false;
		}


	}


	closesocket(clientSocket);

	return true;

}

bool PortScanner::isUdpPortOpen(const std::string& ipAddress, unsigned short port) {

	SOCKET client_socket;

	//create a udp socket
	
	client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (client_socket == INVALID_SOCKET) {

		std::cerr << "failed to create a udp socket. Error:" << getWinsockError() << std::endl;
		return false;
	}

	//set the server addr and the port

	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);//host to network short
	inet_pton(AF_INET, ipAddress.c_str(), &server_addr.sin_addr.s_addr);

	//send a packet ( it can even be a free packet)

	const char* sendData = "test";
	sendto(client_socket, sendData, strlen(sendData), 0,
		reinterpret_cast<SOCKADDR*>(&server_addr), sizeof(server_addr)); 

	

	//Listen for response (with timeout)

	DWORD timeout = 500; //500 ms timeout
	setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO,
		reinterpret_cast<const char*>(&timeout), sizeof(timeout));

	char recvBuffer[512];
	int recvResult = recv(client_socket, recvBuffer, sizeof(recvBuffer), 0);

	//close the sources
	closesocket(client_socket);

	//check the response

	if (recvResult > 0) {
		std::cout << "Response received, Port: " << port << " is open (UDP)." << std::endl;
		return true;
	}	

		int error = getWinsockError();
		if (error == WSAETIMEDOUT) {
		
			std::cout << "Port " << port << " no response (open|filtered)." << std::endl;
			return false;
		}
		else if (error == WSAECONNRESET) { // ICMP Port unreachable
			// Port is closed
			std::cout << "Port " << port << " is closed (ICMP unreachable)" << std::endl;
			return false;
		}
		else {
			std::cerr << "Other Winsock error on Port " << port << ": " << error << std::endl;
			return false;
		}
}

std::string PortScanner::getTCPServiceInfo(const std::string & ipAddress, unsigned short port) {

	SOCKET client_socket;

	client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_socket == INVALID_SOCKET) {

		return "ERROR: Failed to create socket.";
	}

	//set the server addr and the port
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);

	inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr.s_addr);


	//set timeout
	DWORD timeout = 1000; //wait for 1 second.

	setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO,
		reinterpret_cast<const char*>(&timeout), sizeof(timeout));

	//connect
	if (connect(client_socket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {

		closesocket(client_socket);
		return "Closed or filtered port";
	}

	//get the response

	char buffer[1024] = { 0 };
	int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);

	closesocket(client_socket);

	if (bytes_received > 0) {

		//transform the incoming data to string
		return std::string(buffer, bytes_received);
	}
	else if (bytes_received == 0) {
		return "No banner(connection is closed";
	}
	else {
		//error
		int error = getWinsockError();

		return "Error:recv failed with error" + std::to_string(error);
	}

}

std::string PortScanner::getUdpServiceInfo(const std::string& ipAddress, unsigned short port) {
	SOCKET client_socket;

	// Create a UDP socket
	client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (client_socket == INVALID_SOCKET) {
		return "ERROR: Failed to create UDP socket.";
	}

	//Set a 500ms timeout
	DWORD timeout = 500;
	setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO,
		reinterpret_cast<const char*>(&timeout), sizeof(timeout));

	// Set the server address and port
	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, ipAddress.c_str(), &server_addr.sin_addr.s_addr);

	// Send a test packet to the service
	const char* sendData = "test";
	sendto(client_socket, sendData, strlen(sendData), 0,
		reinterpret_cast<SOCKADDR*>(&server_addr), sizeof(server_addr));

	// wait for response
	char recvBuffer[512] = { 0 };
	int recvResult = recv(client_socket, recvBuffer, sizeof(recvBuffer), 0);

	// close the resources
	closesocket(client_socket);

	// check for response 
	if (recvResult > 0) {
		//return the incoming data 
		return std::string(recvBuffer, recvResult);
	}

	int error = getWinsockError();
	if (error == WSAETIMEDOUT) {
		// Timeout error  port could be filtered or close
		return "No response (timeout).";
	}
	else if (error == WSAECONNRESET) {
		// ICMP Port reachable error port is closed
		return "Port closed (ICMP Unreachable).";
	}
	else {
		// Other errors...
		return "ERROR: recv failed with error " + std::to_string(error);
	}
}


std::string PortScanner::getOSInfo(const std::string& ipAddress) {
	SOCKET rawSocket;

	// Create a raw socket. This requires administrator privileges on Windows.
	rawSocket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, NULL);
	if (rawSocket == INVALID_SOCKET) {
		int error = getWinsockError();
		if (error == WSAEACCES) {
			return "ERROR: Raw sockets require administrator privileges (WSAEACCES).";
		}
		return "ERROR: Failed to create raw socket. Error: " + std::to_string(error);
	}

	// Create a buffer for the TCP/IP packet. 20 bytes for IP header + 20 for TCP header.
	char sendBuffer[40];
	memset(sendBuffer, 0, sizeof(sendBuffer));

	// Set up pointers to the IP and TCP headers.
	// This allows us to access packet fields directly using the structs.
	IP_HEADER* ipHeader = reinterpret_cast<IP_HEADER*>(sendBuffer);
	TCP_HEADER* tcpHeader = reinterpret_cast<TCP_HEADER*>(sendBuffer + sizeof(IP_HEADER));

	// Fill in the IP header with standard values.
	ipHeader->ip_version = 4;
	ipHeader->ip_header_len = 5;
	ipHeader->ip_tos = 0;
	ipHeader->ip_total_length = htons(40);
	ipHeader->ip_id = htons(123);
	ipHeader->ip_frag_offset = 0;
	ipHeader->ip_ttl = 128; // Default TTL for Windows. We'll check the response's TTL.
	ipHeader->ip_protocol = IPPROTO_TCP;

	// Fill in the TCP header.
	tcpHeader->tcp_src_port = htons(54321); // A random, non-privileged source port
	tcpHeader->tcp_dest_port = htons(80);   // Common destination port like HTTP
	tcpHeader->tcp_sequence = 123456789;
	tcpHeader->tcp_acknowledgement = 0;
	tcpHeader->tcp_header_length = 5;
	tcpHeader->tcp_flags = 2; // Set the SYN flag to initiate a connection
	tcpHeader->tcp_window_size = htons(65535); // A typical default window size

	// Set the destination address for the `sendto` function.
	sockaddr_in destaddr;
	destaddr.sin_family = AF_INET;
	inet_pton(AF_INET, ipAddress.c_str(), &destaddr.sin_addr.s_addr);
	destaddr.sin_port = tcpHeader->tcp_dest_port;

	// Send the crafted SYN packet to the destination.
	int bytesSent = sendto(rawSocket, sendBuffer, sizeof(sendBuffer), 0,
		reinterpret_cast<SOCKADDR*>(&destaddr), sizeof(destaddr));

	if (bytesSent == SOCKET_ERROR) {
		closesocket(rawSocket);
		return "ERROR: sendto failed. Error: " + std::to_string(getWinsockError());
	}

	// Wait for a response. The buffer must be large enough to hold any incoming IP packet.
	char recvBuffer[65535];
	int bytesReceived = recv(rawSocket, recvBuffer, sizeof(recvBuffer), 0);

	closesocket(rawSocket);

	if (bytesReceived > 0) {

		IP_HEADER* receivedIpHeader = reinterpret_cast<IP_HEADER*>(recvBuffer);

		if (receivedIpHeader->ip_protocol != IPPROTO_TCP) {
			return "OS detection failed : not a TCP response";
		}

		//calculate the length of the IP header in bytes
		int ipHeaderLen = receivedIpHeader->ip_header_len * 4;

		//cast the buffer to a TCP header pointer starting after the IP header
		TCP_HEADER* receivedTcpHeader = reinterpret_cast<TCP_HEADER*>(recvBuffer + ipHeaderLen);

		//get the ttl(time to live) from the received packet using the helper func
		int ttl = getTTL(receivedIpHeader);

		//get the tcp window size. 
		unsigned short window_size = ntohs(receivedTcpHeader->tcp_window_size);

		//calculate the length of tcp options. the default tcp header is 20 bytes

		int tcpHeaderLen = receivedTcpHeader->tcp_header_length * 4;
		int optionsLength = tcpHeaderLen - 20;

		//get the tcp options
		const char* tcpOptions = nullptr;

		if (optionsLength > 0) {
			tcpOptions = reinterpret_cast<const char*>(receivedTcpHeader) + 20;
		}

		return analyzeOS(ttl, window_size, tcpOptions,optionsLength);
	}

	return "OS detection failed.";
}

// A new function inside the PortScanner class
int PortScanner::getTTL(const IP_HEADER* receivedIpHeader) {
	if (receivedIpHeader) {
		// Return the TTL value from the IP header.
		return static_cast<int>(receivedIpHeader->ip_ttl);
	}
	return -1; // Return -1 on error
}


std::string PortScanner::analyzeOS(int ttl, unsigned short windowSize, const char* options, int optionsLength) {
	// 1. First, analyze TCP options. This is the most reliable method.
	if (optionsLength > 0) {
		std::map<int, int> tcpOptionsMap;
		const char* currentOption = options;

		while (currentOption < options + optionsLength) {
			unsigned char kind = *currentOption;

			// End of options list
			if (kind == 0) break;
			// No operation, padding byte
			if (kind == 1) {
				currentOption++;
				continue;
			}

			unsigned char length = *(currentOption + 1);
			if (length == 0 || (currentOption + length) > (options + optionsLength)) {
				break;
			}

			tcpOptionsMap[kind] = length;
			currentOption += length;
		}

		// Now, analyze the collected options to find patterns.
		if (tcpOptionsMap.count(8) > 0) { // Kind 8 is Timestamps
			// Timestamps are common in modern Windows and macOS.
			return "OS: Likely Windows/macOS (TTL: " + std::to_string(ttl) + ", Has Timestamps)";
		}
		if (tcpOptionsMap.count(4) > 0) { // Kind 4 is SACK Permitted
			// SACK is a strong indicator of Linux.
			return "OS: Likely Linux (TTL: " + std::to_string(ttl) + ", Has SACK)";
		}
	}

	// 2. If TCP options are not found or not conclusive, check Window Size.
	if (windowSize == 65535 || windowSize == 16384 || windowSize == 8192) {
		// These are common Window Sizes for Windows OS.
		return "OS: Likely Windows (TTL: " + std::to_string(ttl) + ", WinSize: " + std::to_string(windowSize) + ")";
	}
	else if (windowSize == 5840 || windowSize == 1460) {
		// These are common Window Sizes for Linux OS.
		return "OS: Likely Linux (TTL: " + std::to_string(ttl) + ", WinSize: " + std::to_string(windowSize) + ")";
	}

	// 3. As a last resort, check the TTL value.
	if (ttl <= 64) {
		// Common TTL for Linux/Unix systems.
		return "OS: Linux/Unix (TTL: " + std::to_string(ttl) + ")";
	}
	else if (ttl <= 128) {
		// Common TTL for Windows systems.
		return "OS: Windows (TTL: " + std::to_string(ttl) + ")";
	}

	// If no patterns match, the OS is unknown.
	return "OS: Unknown";
}