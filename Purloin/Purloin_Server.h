#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

BOOL connect(SOCKET* ConnectSocket, PCSTR server_ip, PCSTR server_port);
void close(SOCKET ConnectSocket);
void send(char* data, SOCKET ConnectSocket);
