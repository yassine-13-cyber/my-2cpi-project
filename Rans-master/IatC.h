#pragma once
#include<windows.h>




int RandomCompileTimeSeed(void){
	return '0' - 40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;

}

PVOID Helper(PVOID* ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);

	if (!pAddress) return NULL;

	// setting the first 4 bytes in paddress to be equal to a random number (less than 255)
	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

	// saving the base address by pointer, and returning it
	*ppAddress = pAddress;

	return pAddress;
}

VOID IatCamouflage() {

	PVOID pAddress = NULL;

	int* A = (int*)Helper(&pAddress);

	// impposible if-statement that will never run

	if (*A > 350) {
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);

		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);

		// freeing the buffer allocated in 'Helper'

		HeapFree(GetProcessHeap(), 0, pAddress);
	}
}	 