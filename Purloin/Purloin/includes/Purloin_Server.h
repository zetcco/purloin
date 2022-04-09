#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")

BOOL connect(SOCKET* ConnectSocket, PCSTR server_ip, PCSTR server_port);
void close(SOCKET ConnectSocket);
void send_data(char* data, SOCKET ConnectSocket);
void send_machineName(SOCKET ConnectSocket);
