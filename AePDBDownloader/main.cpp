#include <Windows.h>
#include <string>
#include <urlmon.h>
#include <iomanip>
#include <vector>

#pragma comment(lib, "urlmon.lib")

struct CV_INFO_PDB70
{
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    char PdbFileName[1];
};

std::wstring GetCurrentAppFolder()
{
    wchar_t Buffer[1024];

    GetModuleFileNameW(NULL, Buffer, 1024);

    size_t Pos = std::wstring(Buffer).find_last_of(L"\\/");

    return std::wstring(Buffer).substr(0, Pos + 1);
}

std::string GuidToString(const GUID& guid)
{
    char Buffer[33];

    snprintf(Buffer, sizeof(Buffer), "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    return std::string(Buffer, 32);
}

void CleanupResources(void* pBase, HANDLE hMapping, HANDLE hFile)
{
    if (pBase)
        UnmapViewOfFile(pBase);

    if (hMapping && hMapping != INVALID_HANDLE_VALUE)
        CloseHandle(hMapping);

    if (hFile && hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
}

std::wstring GenerateFileName(std::string FileName, const std::string& FullHex)
{
    size_t Pos = FileName.rfind(".pdb");
    std::string Result;

    FileName = FileName.substr(0, Pos);
    Result = FileName + "_" + FullHex + ".pdb";

    return std::wstring(Result.begin(), Result.end());
}

int HandleFile(const wchar_t* FilePath)
{
    if (GetFileAttributesW(FilePath) == INVALID_FILE_ATTRIBUTES)
    {
        printf_s("[-] File not found! :(\n\n");

        return 2;
    }

    HANDLE hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("[-] CreateFile failed! :(\n\n");

        return 3;
    }

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (!hMapping)
    {
        CleanupResources(nullptr, nullptr, hFile);
        printf_s("[-] CreateFileMapping failed! :( Code: %d\n\n", GetLastError());

        return 4;
    }

    void* pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    if (!pBase)
    {
        CleanupResources(nullptr, hMapping, hFile);
        printf_s("[-] MapViewOfFile failed! :( Code: %d\n\n", GetLastError());

        return 5;
    }

    PIMAGE_DOS_HEADER DosHeader = static_cast<PIMAGE_DOS_HEADER>(pBase);

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] Not a valid PE file! :(\n\n");

        return 6;
    }

    PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pBase) + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] Not a valid PE file (NT signature)! :(\n\n");

        return 7;
    }

    DWORD DebugDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    DWORD DebugDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

    if (!DebugDirRVA || !DebugDirSize)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] No debug directory found! :(\n\n");

        return 8;
    }

    PIMAGE_DEBUG_DIRECTORY DebugDir = nullptr;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);

    for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++Section)
    {
        if (DebugDirRVA >= Section->VirtualAddress && DebugDirRVA < Section->VirtualAddress + Section->Misc.VirtualSize)
        {
            DWORD offset = DebugDirRVA - Section->VirtualAddress + Section->PointerToRawData;
            DebugDir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(reinterpret_cast<BYTE*>(pBase) + offset);

            break;
        }
    }

    if (!DebugDir)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] Debug directory section not found! :(\n\n");

        return 9;
    }

    CV_INFO_PDB70* CvInfo = nullptr;
    char* PDBNamePtr = nullptr;
    GUID Guid = { 0 };
    DWORD Age = 0;
    std::string PDBFullName;

    for (DWORD i = 0; i < DebugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
    {
        if (DebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            CvInfo = reinterpret_cast<CV_INFO_PDB70*>(reinterpret_cast<BYTE*>(pBase) + DebugDir[i].PointerToRawData);

            if (CvInfo && CvInfo->CvSignature == 0x53445352)
            {
                Guid = CvInfo->Signature;
                Age = CvInfo->Age;
                PDBNamePtr = CvInfo->PdbFileName;

                if (PDBNamePtr)
                    PDBFullName = PDBNamePtr;

                break;
            }
        }
    }

    if (PDBFullName.empty())
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] No CodeView debug information found! :(\n\n");

        return 10;
    }

    printf_s("[+] PDB info found! Name: %s\n", PDBFullName.c_str());
    CleanupResources(pBase, hMapping, hFile);

    size_t Pos = PDBFullName.find_last_of("\\/");
    std::string PDBFileName = (Pos != std::string::npos) ? PDBFullName.substr(Pos + 1) : PDBFullName;

    char AgeBuffer[9];

    sprintf_s(AgeBuffer, "%X", Age);

    std::string Url = "http://msdl.microsoft.com/download/symbols/";
    std::string FullHex = GuidToString(Guid) + AgeBuffer;
    Url += PDBFileName + "/" + FullHex + "/" + PDBFileName;

    std::wstring SaveDir = GetCurrentAppFolder() + L"Symbols\\";

    CreateDirectoryW(SaveDir.c_str(), nullptr);

    std::wstring UrlW(Url.begin(), Url.end());
    std::wstring SavePath = SaveDir + GenerateFileName(PDBFileName, FullHex);

    printf_s("[*] Downloading: %ls\n", UrlW.c_str());

    HRESULT hResult = URLDownloadToFileW(nullptr, UrlW.c_str(), SavePath.c_str(), 0, nullptr);

    if (hResult == S_OK)
    {
        printf_s("[*] Saving to: %ls\n[+] Downloaded successfully!\n\n", SavePath.c_str());
    }
    else
    {
        printf_s("[-] Download failed! :( Code: 0x%X\n\n", static_cast<unsigned long>(0x80070002));
    }

    return 0;
}

int wmain(int argc, wchar_t* argv[])
{
    printf_s("\n------\nPDB downloader by Aeterts\n\n");

    if (argc < 2)
    {
        printf_s("[!] Usage: %ls \"Path_to_PE_files\"\n", argv[0]);

        return 1;
    }

    int Result = 0;

    for (int i = 1; i < argc; i++)
    {
        printf_s("[*] Processing %ls file...\n", argv[i]);

        Result = HandleFile(argv[i]);

        if (Result != 0)
            break;
    }

    printf_s("------\n");

    return Result;
}