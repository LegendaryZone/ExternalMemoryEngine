#include "mem.h"

DWORD getProcessId(wchar_t *ProcessName)
{
	//Take a snapshot of all active processes.
	HANDLE hProcessList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	//Check if the snapshot was successful.
	if (hProcessList != INVALID_HANDLE_VALUE)
	{
		//A struct that holds data about the current process.
		PROCESSENTRY32 sEntryProcess;

		//Set the size of the structure.
		sEntryProcess.dwSize = sizeof(sEntryProcess);

		//Check if we can retrieve the first process from the list.
		if (Process32First(hProcessList, &sEntryProcess))
			//Loop through the process list and try to find the given process.
			do {
				//Check to see if the current process matches the given one.
				if (!_wcsicmp(ProcessName, sEntryProcess.szExeFile))
				{
					CloseHandle(hProcessList);
					return sEntryProcess.th32ProcessID;
				}
			} while (Process32Next(hProcessList, &sEntryProcess));
	}

	//Something failed.
	CloseHandle(hProcessList);
	return 0;
}

MODULEENTRY32 getModule(DWORD ProcessId, wchar_t *ModuleName)
{
	if (!ProcessId)
		return { 0 };

	//A struct that holds data about the current module.
	MODULEENTRY32 sEntryModule = { 0 };

	//Take a snapshot of the given process modules (x32 and x64).
	HANDLE hModuleList = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);

	//Check if the snapshot was successful.
	if (hModuleList != INVALID_HANDLE_VALUE)
	{
		//Set the size of the structure.
		sEntryModule.dwSize = sizeof(sEntryModule);

		//Check if we can retrieve the first module from the list.
		if (Module32First(hModuleList, &sEntryModule))
			//Loop through the module list and try to find the given module.
			do {
				//Check to see if the current module matches the given one.
				if (!_wcsicmp(ModuleName, sEntryModule.szModule))
				{
					CloseHandle(hModuleList);
					return sEntryModule;
				}
			} while (Module32Next(hModuleList, &sEntryModule));
	}

	//Something failed.
	CloseHandle(hModuleList);
	return { 0 };
}

BOOL readAddress(void *AddressValue, size_t DataSize, uintptr_t Address, HANDLE hProcess)
{
	//Attempt to read the address value.
	return ReadProcessMemory(hProcess, (BYTE*)Address, AddressValue, DataSize, NULL);
}

uintptr_t getAddress(uintptr_t BaseAddress, std::vector<uintptr_t> vOffsets, HANDLE hProcess)
{
	//Temporary address used to resolve the base address.
	uintptr_t Address = BaseAddress;

	//Number of offsets
	int OffsetCount = vOffsets.size();

	//Resolve the base address.
	for (int i = 0; i < OffsetCount; i++)
		if (readAddress(&Address, sizeof(Address), Address, hProcess))
			Address += vOffsets[i];

	return Address;
}

BOOL writeAddress(void *Data, size_t DataSize, uintptr_t Address, HANDLE hProcess)
{
	//Attempt to write the given data at the address location.
	return WriteProcessMemory(hProcess, (BYTE*)Address, Data, DataSize, NULL);
}

uintptr_t getOffset(uintptr_t BaseAddress, size_t ModuleSize, const char *Signature, const char *SignatureMask, HANDLE hProcess)
{
	if (!BaseAddress)
		return 0;

	//So we know when to stop searching.
	BOOL Found = FALSE;
	//Index to step through each of the module's addresses.
	int Step = 0;
	//The number of bytes to scan.
	int SignatureSize = strlen(SignatureMask);

	//The bytes we are going to read.
	BYTE *BytesRead = (BYTE *)calloc(SignatureSize + 1, sizeof(BYTE));

	//Start scanning.
	do {
		//The current address.We start from here and scan 'SignatureSize' number of bytes.
		uintptr_t CurrentAddress = BaseAddress + Step;

		//Read the current address and save the first 'SignatureSize' number of bytes.
		if (ReadProcessMemory(hProcess, (BYTE*)CurrentAddress, BytesRead, SignatureSize, NULL))
		{
			//We assume we have found the address.
			Found = TRUE;
			//We step through each read byte.
			for (int i = 0; i < SignatureSize; i++)
				//If the mask indicates that there is a valid byte, we then compare each read byte with the ones from our signature.
				//This statement is negated.
				if (SignatureMask[i] == 'x' && (BYTE)Signature[i] != BytesRead[i])
				{
					//The read bytes didn't match our signature so we stop comparing.
					Found = FALSE;
					break;
				}
		}

		//We go to the next address.
		Step++;
	} while (Found == FALSE && Step < ModuleSize);

	//If our signature matches the read bytes, we assume we have found the offset and return it.
	//This method of parsing the bytes is easily customizable.
	if (Found)
	{
		//Temporary buffer used for conversion.
		char TempBuffer[17] = "";	//17 = Two octets + 1 (to support 64bit addresses)

		//We step through our read bytes once more in order to extract our offset.
		for (int i = SignatureSize - 1; i >= 0; i--)
			//We extract the offset.
			if (SignatureMask[i] == '?')
			{
				//We convert each byte to a char array.
				char CurrentByte[3] = "";
				//Convert byte to hex
				sprintf(CurrentByte, "%.2X", (uintptr_t)(BytesRead[i]));

				//We concatenate each converted byte to our temporary buffer.
				strcat(TempBuffer, CurrentByte);
			}
		//We free our memory.
		free(BytesRead);

		//We convert our temporary char array to an unsigned int and return it.
		return (uintptr_t)(strtoul(TempBuffer, NULL, 16));
	}

	//We have failed to find the offset.

	//We free our memory.
	free(BytesRead);
	return 0;
}
