#pragma once
#pragma warning(disable:4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <vector>

/*
*More information about the used functions and structures here, in usage order:
*
*CreateToolhelp32Snapshot()	= https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
*Process32First()			= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/nf-tlhelp32-process32first
*Process32Next()			= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/nf-tlhelp32-process32next
*PROCESSENTRY32 structure	= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/ns-tlhelp32-tagprocessentry32
*Module32First()			= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/nf-tlhelp32-module32first
*Module32Next()				= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/nf-tlhelp32-module32next
*MODULEENTRY32 structure	= https://docs.microsoft.com/ro-ro/windows/desktop/api/tlhelp32/ns-tlhelp32-tagmoduleentry32

*ReadProcessMemory()		= https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-readprocessmemory
*WriteProcessMemory()		= https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory
*/

/*
*A class used to read/write data to memory.
*/
class mem
{
public:

	/*
	*Returns the PID of the given process or 0 if it fails.
	*Parameters:
	*	<wchar_t *>Name of the process.
	*/
	DWORD getProcessId(wchar_t *);

	/*
	*Returns a module struct holding the given module's information or and empty module if it fails.
	*Parameters:
	*	<DWORD>PID.
	*	<wchar_t *>Name of the module.
	*/
	MODULEENTRY32 getModule(DWORD, wchar_t *);

	/*
	*Reads the data located at the given address and returns it through the first parameter.
	*You need to specify the size of the data type through the second parameter.
	*Returns TRUE if reading the address succeeds or FALSE if it fails.
	*Parameters:
	*	<void *>Address value.
	*	<size_t>Data type size.
	*	<uintptr_t>Address.
	*	<HANDLE>A read-access HANDLE to the target process.
	*/
	BOOL readAddress(void *, size_t, uintptr_t, HANDLE);

	/*
	*Returns the address pointed to by the given set of offsets.
	*Parameters:
	*	<uintptr_t>The base address.
	*	<vector<uintptr_t>>The offsets vector.
	*	<HANDLE>A read-access HANDLE to the target process.
	*/
	uintptr_t getAddress(uintptr_t, std::vector<uintptr_t>, HANDLE);

	/*
	*Writes the given data to the target address.Returns TRUE if it succeeds and FALSE otherwise.
	*You need to specify the size of the data type through the second parameter.
	*Parameters:
	*	<void *>Data to be written.
	*	<size_t>Data type size.
	*	<uintptr_t>Address.
	*	<HANDLE>A write-operation-access HANDLE to the target process.
	*/
	BOOL writeAddress(void *, size_t, uintptr_t, HANDLE);

	/*
	*Scans the entire module until it finds the given bytes pattern.
	*Returns an offset based on the given signature or 0 if it fails.
	*Parameters:
	*	<uintptr_t>The module address.
	*	<size_t>The size of the module in bytes.
	*	<const char *>The signature.
	*	<const char *>The signature mask.
	*	<HANDLE>A read-access HANDLE to the target process.
	*/
	uintptr_t getOffset(uintptr_t, size_t, const char *, const char *, HANDLE);

};

