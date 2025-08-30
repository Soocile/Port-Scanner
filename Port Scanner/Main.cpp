
#include"PORTSCANNER.hpp"
#include<iostream>

int main(int argc, char** argv) {

	try {

		PortScanner scanner;


		//tcp scan on localhost
		scanner.scan("127.0.0.1", 1, 1024, PortScanner::TCP);

		//udp scan on localhost
	//scanner.scan("127.0.0.1",1,1024,PortScanner::UDP);

	}
	catch (std::exception& e) {

		std::cerr << "Error:" << e.what() << std::endl;
	}


	return 0;
}