#include "Purloin/Purloin_Server.h"

#define DEFAULT_BUFLEN 512

BOOL connect(SOCKET* ConnectSocket, PCSTR server_ip, PCSTR server_port) {
	WSADATA wsaData;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	//char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	//int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "WSAStartup failed with error: %d\n", iResult);
		return FALSE;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(server_ip, server_port, &hints, &result);
	if (iResult != 0) {
		// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return FALSE;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		*ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (*ConnectSocket == INVALID_SOCKET) {
			// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return FALSE;
		}

		// Connect to server.
		iResult = connect(*ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(*ConnectSocket);
			*ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (*ConnectSocket == INVALID_SOCKET) {
		// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Unable to connect to server!\n");
		WSACleanup();
		return FALSE;
	}
}

void send(char* data, SOCKET ConnectSocket) {
	// Send an initial buffer
	int iResult;
	iResult = send(ConnectSocket, data, (int)strlen(data), 0);
	//iResult = send(ConnectSocket, "\n", 1, 0);
	if (iResult == SOCKET_ERROR) {
		// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
	}
	memset(data, 0, DEFAULT_BUFLEN);
}

void close(SOCKET ConnectSocket) {
	// shutdown the connection since no more data will be sent
	int iResult;
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		// sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();
}