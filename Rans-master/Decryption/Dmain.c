#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include"commonDec.h"
#include"aes.h"



INT DecryptionFunction() {
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
	PBYTE encKeyValue = NULL;
	PBYTE iv = NULL;
	SIZE_T  szkey = AES_256_KEY_SIZE;
	SIZE_T  szkeyRead = NULL;
	SIZE_T  szIvRead = NULL;
	WCHAR	userName[MAX_PATH * sizeof(WCHAR)];
	WCHAR	keyPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR	directoryPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	WCHAR	ivPath[MAX_PATH * sizeof(WCHAR)] = L"C:\\Users\\";
	SIZE_T	szName = MAX_PATH * sizeof(WCHAR);

	if (!GetUserNameW(userName, &szName)) {
		printf("[!] GetUserName failed with %d", GetLastError());
		return -1;
	}

	StringCchCat(keyPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(keyPath, MAX_PATH * sizeof(WCHAR), L"\\Documents\\AES_key");

	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(ivPath, MAX_PATH * sizeof(WCHAR), L"\\Documents\\IV");

	if (!ReadFromFile(&encKeyValue, keyPath, &szkeyRead)) {
		printf("[!] ReadFromFile Failed with %d\n", GetLastError());
		return -1;
	}
	if (!ReadFromFile(&iv, ivPath, &szIvRead) || szIvRead != IV_SIZE) {
		printf("[!] ReadFromFile Failed with %d\n", GetLastError());
		return -1;
	}

	printf("[+] Encrypted AES Key (%d bytes):\n", szkeyRead);
	for (int i = 0; i < szkeyRead; i++) {
		printf("%02X ", encKeyValue[i]);
	}

	printf("\n\n");


	printf("[+] IV:\n");
	for (int i = 0; i < IV_SIZE; i++) {
		printf("%02X ", iv[i]);
	}
	printf("\n");

	if (!ImportPrivkey(&hCryptProv, &hKey)) {
		return -1;
	}

	if (!DecryptAESKey(hKey, encKeyValue, &szkeyRead)) {
		return -1;
	}

	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), userName);
	StringCchCat(directoryPath, MAX_PATH * sizeof(WCHAR), L"\\Documents");


	printf("[*]Press Enter to Decrypt the files... \n");
	getchar();

	if (!DirectoryFiles(directoryPath, encKeyValue, iv)) {
		printf("[!] DerecotryFiles don't work %d\n", GetLastError());
		return -1;
	}


	printf("\nDone!\n");


	getchar();


	return 0;





}

int main() {

	DecryptionFunction();

	return 0;
}