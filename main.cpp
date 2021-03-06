#include <iostream>
#include "mem.h"

typedef struct {
	char LocalPlayer[64];
	char Name[64];
	char Health[64];
	char Armor[64];
	char TargetName[64];
}SIGNATURES;

typedef struct {
	char LocalPlayer[64];
	char Name[64];
	char Health[64];
	char Armor[64];
	char TargetName[64];
}MASKS;

typedef struct {
	uintptr_t LocalPlayer;
	uintptr_t Name;
	uintptr_t Health;
	uintptr_t Armor;
	uintptr_t TargetName;
}OFFSETS;

typedef struct {
	uintptr_t LocalPlayer;
	uintptr_t Name;
	uintptr_t Health;
	uintptr_t Armor;
}PLAYER;


int main()
{
	std::cout << "Last build: " << __DATE__ << " " << __TIME__ << std::endl;


	DWORD ProcessId = getProcessId(L"ac_client.exe");

	MODULEENTRY32 Module = getModule(ProcessId, L"ac_client.exe");

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ProcessId);

	uintptr_t ModuleAddr = (uintptr_t)Module.modBaseAddr;
	size_t ModuleSize = (uintptr_t)Module.modBaseSize;

	/*NOTE: When using string manipulation functions like strcpy, the char byte arrays will be
	*messed up after reaching the first /x00 due to \0 being the str terminator.So make sure when
	*initializing the signature strings, to NOT use any string manipulation functions.
	*/
	SIGNATURES sSignatures = {
		"\xA1\x00\x00\x00\x00\x3B\xC8\x74\x1B",			//LocalPlayer
		"\x8D\xB7\x00\x00\x00\x00\x80\x3E",				//Name
		"\x8B\x83\x00\x00\x00\x00\x83",					//Health
		"\x8B\x86\x00\x00\x00\x00\x85\xC0\x74\x29",		//Armor
		"\xBA\x00\x00\x00\x00\x2B\xD0\x8A\x08"			//TargetName
	};
	MASKS sMasks = {
		"x????xxxx",	//LocalPlayer
		"xx????xx",		//Name
		"xx????x",		//Health
		"xx????xxxx",	//Armor
		"x????xxxx"		//TargetName
	};
	OFFSETS sOffsets = { 0 };
	PLAYER sPlayer = { 0 };

	sOffsets.LocalPlayer = getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.LocalPlayer, sMasks.LocalPlayer, hProcess);
	sOffsets.Name = getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Name, sMasks.Name, hProcess);
	sOffsets.Health = getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Health, sMasks.Health, hProcess);
	sOffsets.Armor = getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Armor, sMasks.Armor, hProcess);
	sOffsets.TargetName = getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.TargetName, sMasks.TargetName, hProcess);

	std::cout << "We got the offsets..." << std::endl;

	sPlayer.LocalPlayer = sOffsets.LocalPlayer;
	sPlayer.Name = getAddress(sPlayer.LocalPlayer, { sOffsets.Name }, hProcess);
	sPlayer.Health = getAddress(sPlayer.LocalPlayer, { sOffsets.Health }, hProcess);
	sPlayer.Armor = getAddress(sPlayer.LocalPlayer, { sOffsets.Armor }, hProcess);

	std::cout << "We got the addresses..." << std::endl;

	char Name[32] = "";
	char TargetName[32] = "";
	int Health = 0;
	int Armor = 0;

	readAddress(Name, sizeof(Name), sPlayer.Name, hProcess);
	readAddress(&Health, sizeof(Health), sPlayer.Health, hProcess);
	readAddress(&Armor, sizeof(Armor), sPlayer.Armor, hProcess);
	readAddress(TargetName, sizeof(TargetName), sOffsets.TargetName, hProcess);

	std::cout << "We got the values..." << std::endl;

	std::cout << "Player name: " << Name << std::endl;
	std::cout << "Player health: " << Health << std::endl;
	std::cout << "Player armor: " << Armor << std::endl;
	std::cout << "Target name: " << TargetName << std::endl;

	CloseHandle(hProcess);
	getchar();
	return 0;
}

