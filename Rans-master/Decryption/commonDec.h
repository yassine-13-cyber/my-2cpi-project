#pragma once
#include <windows.h>
#include "aes.h"


#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  



BOOL RemovePadding(uint8_t* ciphertext, SIZE_T* szciphertext);

VOID AESdecryptFile(uint8_t* key, uint8_t* iv, uint8_t* ciphertext);

BOOL ReadFromFile(PBYTE* pData, WCHAR* filePath, SIZE_T* szData);

BOOL WriteToFile(PBYTE buffer, WCHAR* filePath, SIZE_T numberOfBytesToWrite);

BOOL DirectoryFiles(LPWSTR pDirectoryPath, BYTE* key, BYTE* iv);

BOOL ImportPrivkey(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey);

BOOL DecryptAESKey(HCRYPTKEY hKey, PBYTE key, SIZE_T* keySize);
