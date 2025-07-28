#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <filesystem>

struct CV_INFO_PDB70
{
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    char PdbFileName[1];
};

std::string GuidToString(const GUID& guid)
{
    char Buffer[33];

    snprintf(Buffer, sizeof(Buffer), "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    return std::string(Buffer, 32);
}

std::wstring GenerateFileName(std::string FileName, const std::string& FullHex)
{
    size_t Pos = FileName.rfind(".pdb");
    std::string Result;

    FileName = FileName.substr(0, Pos);
    Result = FileName + "_" + FullHex + ".pdb";

    return std::wstring(Result.begin(), Result.end());
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

std::wstring FindPdbFileByBaseName(const std::filesystem::path& SymbolsPath, const std::wstring& PdbPath)
{
    std::filesystem::path Path(PdbPath);
    std::wstring BaseName = Path.stem();

    for (const auto& Entry : std::filesystem::directory_iterator(Path.has_parent_path() ? Path.parent_path() : SymbolsPath))
    {
        if (Entry.is_regular_file())
        {
            std::wstring FileName = Entry.path().filename();

            if (FileName.size() > BaseName.size() + 1 && FileName.substr(0, BaseName.size() + 1) == BaseName + L"_" &&
                _wcsicmp(FileName.substr(FileName.size() - 4).c_str(), L".pdb") == 0)
            {
                return Entry.path();
            }
        }
    }

    return L"";
}

int HandleFile(const std::filesystem::path& SymbolsPath, const std::filesystem::path& FilePath, std::wstring& NewPDBName, std::vector<std::wstring>& OldFiles)
{
    if (!std::filesystem::exists(FilePath))
    {
        printf_s("[-] File not found! :(\n\n");

        return 3;
    }

    HANDLE hFile = CreateFileW(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("[-] CreateFile failed! :(\n\n");

        return 4;
    }

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (!hMapping)
    {
        CleanupResources(nullptr, nullptr, hFile);
        printf_s("[-] CreateFileMapping failed! :( Code: %d\n\n", GetLastError());

        return 5;
    }

    void* pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    if (!pBase)
    {
        CleanupResources(nullptr, hMapping, hFile);
        printf_s("[-] MapViewOfFile failed! :( Code: %d\n\n", GetLastError());

        return 6;
    }

    PIMAGE_DOS_HEADER DosHeader = static_cast<PIMAGE_DOS_HEADER>(pBase);

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] Not a valid PE file! :(\n\n");

        return 7;
    }

    PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pBase) + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] Not a valid PE file (NT signature)! :(\n\n");

        return 8;
    }

    DWORD DebugDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    DWORD DebugDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

    if (!DebugDirRVA || !DebugDirSize)
    {
        CleanupResources(pBase, hMapping, hFile);
        printf_s("[-] No debug directory found! :(\n\n");

        return 9;
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

        return 10;
    }

    CV_INFO_PDB70* CvInfo = nullptr;
    char* PDBNamePtr = nullptr;
    GUID Guid = {0};
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

        return 11;
    }

    CleanupResources(pBase, hMapping, hFile);

    size_t Pos = PDBFullName.find_last_of("\\/");
    std::string PDBFileName = (Pos != std::string::npos) ? PDBFullName.substr(Pos + 1) : PDBFullName;

    char AgeBuffer[9];

    sprintf_s(AgeBuffer, "%X", Age);

    std::string FullHex = GuidToString(Guid) + AgeBuffer;

    std::wstring FileName = GenerateFileName(PDBFileName, FullHex);

    std::filesystem::path PDBPath = SymbolsPath / FileName;

    NewPDBName = FileName;

    if (std::filesystem::exists(PDBPath))
        return 0;

    std::filesystem::path DownloadedPDBPath = FindPdbFileByBaseName(SymbolsPath, std::wstring(PDBFileName.begin(), PDBFileName.end()));
    std::wstring DownloadedPDBName = DownloadedPDBPath.filename();

    if (DownloadedPDBName.empty())
        return 2;

    size_t FirstPos = DownloadedPDBName.find_last_of('_');
    size_t LastPos = DownloadedPDBName.find(L".pdb");

    if (std::wstring(FullHex.begin(), FullHex.end()) != DownloadedPDBName.substr(FirstPos + 1, LastPos - FirstPos - 1))
    {
        OldFiles.push_back(DownloadedPDBPath.wstring());

        return 1;
    }

    return 12;
}

int wmain(int argc, wchar_t* argv[])
{
    setlocale(LC_ALL, ".UTF-8");
    printf_s("\n------\nPDB updater by Aeterts\n\n");

    if (argc < 3 || argc % 2 != 1)
    {
        printf_s("[!] Usage: %ls \"Path_to_PE_file1\" \"Symbol1, Symbol2, ...\" \"Path_to_PE_file2\" \"Symbol1, Symbol2, ...\"...\n", argv[0]);

        return 1;
    }

    wchar_t CurrentExePath[MAX_PATH];

    if (!GetModuleFileNameW(NULL, CurrentExePath, MAX_PATH))
    {
        wprintf_s(L"[-] GetModuleFileName failed! :( (Error: %d)\n", GetLastError());

        return -1;
    }

    std::filesystem::path AePDBDir(CurrentExePath);
    AePDBDir = AePDBDir.parent_path();

    std::filesystem::path SymbolsPath = AePDBDir / L"Symbols";

    if (!std::filesystem::exists(SymbolsPath))
        std::filesystem::create_directory(SymbolsPath);

    std::wstring DownloaderCmd = AePDBDir / L"AePDBDownloader.exe";
    std::wstring ParserCmd = AePDBDir / L"AePDBParser.exe";

    std::vector<std::wstring> OldFiles;

    bool bNeedUpdate = false;

    for (int i = 1; i < argc; i += 2)
    {
        std::filesystem::path PEPath(argv[i]);

        std::wstring NewPDBName;

        int CheckCode = HandleFile(SymbolsPath, PEPath, NewPDBName, OldFiles);
        bool bUpdateCmd = false;

        switch (CheckCode)
        {
        case 0: printf_s("[+] PDB for %ls is up to date!\n", PEPath.filename().c_str()); break;
        case 1: printf_s("[!] PDB for %ls need update!\n", PEPath.filename().c_str()); bUpdateCmd = true; break;
        case 2: printf_s("[!] PDB for %ls not exist!\n", PEPath.filename().c_str()); bUpdateCmd = true; break;
        default: printf_s("[!] Some error occured while check for update! Code: %d\n", CheckCode); break;
        }

        if (bUpdateCmd)
        {
            bNeedUpdate = true;

            DownloaderCmd += L" \"" + PEPath.wstring() + L"\"";
            ParserCmd += L" \"" + NewPDBName + L"\"" + L" \"" + PEPath.wstring() + L"\"" + L" \"" + argv[i + 1] + L"\"";
        }
    }

    if (!bNeedUpdate)
    {
        printf_s("\n------\n\n");

        return 0;
    }

    int DownloadResult = _wsystem(DownloaderCmd.c_str());

    if (DownloadResult != 0 && !OldFiles.empty())
    {
        printf_s("[-] Update faild while downloading, old files will not be removed! :( Code: %d\n", DownloadResult);

        return DownloadResult;
    }

    for (const std::wstring& OldFile : OldFiles)
    {
        printf_s("[*] Removing: %ls", OldFile.c_str());
        std::filesystem::remove(OldFile);
    }

    int ParseResult = _wsystem(ParserCmd.c_str());

    if (ParseResult != 0)
    {
        printf_s("[-] Update faild while parsing with! :( Code: %d\n", ParseResult);
    }
    else
    {
        printf_s("\n[+] Successfully updated!\n");
    }

    printf("------\n\n");

    return ParseResult;
}