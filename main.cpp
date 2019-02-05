#include <iostream>
#include "mem.h"

typedef struct {
	char LocalPlayer[64];
	char Name[64];
	char Health[64];
	char Armor[64];
}SIGNATURES;

typedef struct {
	char LocalPlayer[64];
	char Name[64];
	char Health[64];
	char Armor[64];
}MASKS;

typedef struct {
	uintptr_t LocalPlayer;
	uintptr_t Name;
	uintptr_t Health;
	uintptr_t Armor;
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

	mem mem;

	DWORD ProcessId = mem.getProcessId(L"ac_client.exe");

	MODULEENTRY32 Module = mem.getModule(ProcessId, L"ac_client.exe");

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ProcessId);

	uintptr_t ModuleAddr = (uintptr_t)Module.modBaseAddr;
	size_t ModuleSize = (uintptr_t)Module.modBaseSize;

	SIGNATURES sSignatures = { 0 };
	MASKS sMasks = { 0 };
	OFFSETS sOffsets = { 0 };
	PLAYER sPlayer = { 0 };

	strcpy_s(sSignatures.LocalPlayer, "/xA1/x00/x00/x00/x00/x3B/xC8/x74/x1B");
	strcpy_s(sSignatures.Name, "/x8D/xB7/x00/x00/x00/x00/x80/x3E");
	strcpy_s(sSignatures.Health, "/x8B/x83/x00/x00/x00/x00/x83");
	strcpy_s(sSignatures.Armor, "/x8B/x86/x00/x00/x00/x00/x85/xC0/x74/x29");

	strcpy_s(sMasks.LocalPlayer, "x????xxxx");
	strcpy_s(sMasks.Name, "xx????xx");
	strcpy_s(sMasks.Health, "xx????x");
	strcpy_s(sMasks.Armor, "xx????xxxx");

	sOffsets.LocalPlayer = mem.getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.LocalPlayer, sMasks.LocalPlayer, hProcess);
	sOffsets.Name = mem.getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Name, sMasks.Name, hProcess);
	sOffsets.Health = mem.getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Health, sMasks.Health, hProcess);
	sOffsets.Armor = mem.getOffset((uintptr_t)Module.modBaseAddr, Module.modBaseSize, sSignatures.Armor, sMasks.Armor, hProcess);

	std::cout << "We got the offsets..." << std::endl;

	sPlayer.LocalPlayer = sOffsets.LocalPlayer;
	sPlayer.Name = mem.getAddress(sPlayer.LocalPlayer, { sOffsets.Name }, hProcess);
	sPlayer.Health = mem.getAddress(sPlayer.LocalPlayer, { sOffsets.Health }, hProcess);
	sPlayer.Armor = mem.getAddress(sPlayer.LocalPlayer, { sOffsets.Armor }, hProcess);

	std::cout << "We got the addresses..." << std::endl;

	char Name[32] = "";
	int Health = 0;
	int Armor = 0;

	mem.readAddress(Name, sizeof(Name), sPlayer.Name, hProcess);
	mem.readAddress(&Health, sizeof(Health), sPlayer.Health, hProcess);
	mem.readAddress(&Armor, sizeof(Armor), sPlayer.Armor, hProcess);

	std::cout << "We got the values..." << std::endl;

	std::cout << "Player name: " << Name << std::endl;
	std::cout << "Player health: " << Health << std::endl;
	std::cout << "Player armor: " << Armor << std::endl;

	CloseHandle(hProcess);
	getchar();
    return 0;
}

