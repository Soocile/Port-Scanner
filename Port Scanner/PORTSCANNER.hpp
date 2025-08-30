
#ifndef PORTSCANNER_HPP
#define PORTSCANNER_HPP


#include<string>
#include<WinSock2.h>
#include<WS2tcpip.h>
#include<vector>
#include<iostream>
#include<map>


class PortScanner {
public:
	// IP and TCP header structures. The pragma pack(1) ensures the structs are byte-aligned.
#pragma pack(1)
	typedef struct ip_header {
		unsigned char  ip_header_len : 4;   // 4 bits for header length
		unsigned char  ip_version : 4;      // 4 bits for IP version (e.g., 4)
		unsigned char  ip_tos;              // Type of service
		unsigned short ip_total_length;     // Total packet length
		unsigned short ip_id;               // Identification
		unsigned short ip_frag_offset;      // Fragment offset
		unsigned char  ip_ttl;              // Time to live
		unsigned char  ip_protocol;         // Protocol (e.g., TCP, UDP)
		unsigned short ip_checksum;         // Header checksum
		unsigned int   ip_srcaddr;          // Source IP address
		unsigned int   ip_destaddr;         // Destination IP address
	} IP_HEADER;

	typedef struct tcp_header {
		unsigned short tcp_src_port;        // Source port
		unsigned short tcp_dest_port;       // Destination port
		unsigned int   tcp_sequence;        // Sequence number
		unsigned int   tcp_acknowledgement; // Acknowledgment number
		unsigned char  tcp_reserved_part1 : 4;
		unsigned char  tcp_header_length : 4;
		unsigned char  tcp_flags;           // Control flags (e.g., SYN, ACK)
		unsigned short tcp_window_size;     // Window size
		unsigned short tcp_checksum;        // Checksum
		unsigned short tcp_urgent_pointer;  // Urgent pointer
	} TCP_HEADER;
#pragma pack()


	enum ScanType {
		TCP,
		UDP
	};

	//constructor function which will create the winsock
	PortScanner();


	//destructor function which will clear the winsock
	~PortScanner();

	void scanWorker(const std::string& ipAddress, unsigned short  startport,
		unsigned  short endPort, ScanType type);


	//starts port scanning
	void scan(const std::string& ipAddress, unsigned short startPort,
		unsigned short endPort, ScanType type);

	std::string getTCPServiceInfo(const std::string& ipAddress, unsigned short port);

	std::string getUdpServiceInfo(const std::string& ipAddress, unsigned short port);

	std::string getOSInfo(const std::string& ipAddress);

private:

	int getTTL(const IP_HEADER* receivedIpHeader);
	std::string analyzeOS(int ttl, unsigned short windowSize, const char* options,
		int optionsLength);

	//controls a specified port if it is open or not.
	bool isTcpPortOpen(const std::string& ipAddress, unsigned short port);


	//in case of error gets the detailed error info from winsock
	static int getWinsockError();

	//UDP support

	bool isUdpPortOpen(const std::string& ipAddress, unsigned short port);

};





#endif //PORTSCANNER_HPP