
# Purloin

win32 API based password stealer.


 - [Dependencies](#dependencies)
 - [How it works](#howitworks)

 

## Dependencies

Other than win32, the only dependency is the SQLite
To install SQLite, use VCPKG.

```bash
vcpkg install sqlite3
vcpkg integrate install
```
## How it works

Chrome passwords are stored in,

```
C:\Users\[user_name]\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

This “Login Data” file is stored in SQLite database format. It contains database table called “logins” where each website login details are stored.
Some of the fields are,

```
origin_url - main link of the website
action_url - login link of the website
username_element - name of the username field in the website
username_value - username used for login
password_element - name of the password field in the website
password_value - password used for login (encrypted)
date_created - date when it is stored
times_used - how many times this password is used
blacklisted_by_user - set to 1 means password is never stored 	
```

Here action_url, username_value and password_value refers to website login link, username and encrypted password respectively.

Based on Chrome version, different password encryption technique is used as explained below.

### Chrome v80.0 and higher

New Chrome version (v80.0 & higher) uses Master Key based encryption to store your web login passwords.

Here is how it generates the Master Key. First 32-byte random data is generated. Then it is encrypted using Windows DPAPI (“CryptProtectData”) function. To this encrypted key, it inserts signature “DPAPI” in the beginning for identification.

Finally this key is encoded using Base64 and stored in “Local State” file in above “User Data” folder.

Below is the sample entry of encrypted master key.

```
"os_crypt":{"encrypted_key":"RFBBUEkBAAAA0Iyd3wEA0RGbegD...opsxEv3TKNqz0gyhAcq+nAq0"},
```

Now to store the web login password, Chrome encrypts it using AES-256-GCM algorithm with the above master key and 12-byte random IV data. Finally, it inserts signature “v10” to the encrypted password and stores it in above “Login Data” file.

Below is the structure of new encrypted password,

```
struct WebPassword
{
	BYTE signature[3] = "v10";
	BYTE iv[12];
	BYTE encPassword[...]
	BYTE tag[16]
}
```

#### Decryption
Currently, only the passwords with ```v10``` are decrypted.

Using the win32's ``` BCryptDecrypt() ``` function,

Below are the data that should be provided for the ``` BCryptDecrypt() ``` function from the datablob. Other parameters can be read from the [BCryptDecrypt() win32 docs](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt).
| Main ```BCryptDecrypt()``` function parameters     | Matching data From Datablob     | Description                |
| :---------------------------------------------- | :-----------------------------  | :------------------------- |
| `pbInput` 									  | `DATABLOB[13:-16]`              | Cipher text to be decrypted |
| `cbInput` 									  | `DATABLOB_SIZE - (3 + 12 + 16)` | Size of the Cipher text. (Whole datablobe size minus the tag,iv,version size which is (3+12+16)) |
| `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.pbNonce` | `DATABLOB[3:12]`                | IV that is needed to decrypt the password |
| `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.cbNonce` | `12 bytes`                            | Size of the IV, which is 12 bytes |
| `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.pbTag`   | `DATABLOB[:-16]`                | Tag that is needed to decrypt the password |
| `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.cbTag`   | `16 bytes`                            | Size of the Tag, which is 16 bytes |


### Chrome v79.0 and older

Older version of Chrome encrypts the website password using Windows DPAPI (“CryptProtectData”) function and stores the encrypted password in above “Login Data” file.

Both Chrome versions uses DPAPI functions perform encryption of password using user and machine specific data. As a result encrypted password cannot be decrypted by another user or on another computer.

Hence Chrome password recovery has to be performed on the same computer as the same user.

#### Decryption

Chrome version (v79.0 or earlier) used Windows DPAPI function, CryptProtectData to encrypt the website password. We can decrypt this password using the function called CryptUnprotectData.
But assuming many of the chrome installations are up-to-date. Decrption of this version's passwords are not included in the program.

