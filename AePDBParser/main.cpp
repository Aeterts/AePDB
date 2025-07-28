#include <Windows.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <map>
#include <set>
#include <fstream>

#pragma comment(lib, "Dbghelp.lib")

std::vector<std::wstring> SplitSymbols(const std::wstring& SymbolsStr)
{
    std::vector<std::wstring> Symbols;
    std::wstringstream StrStream(SymbolsStr);
    std::wstring Symbol;

    while (std::getline(StrStream, Symbol, L','))
    {
        size_t Start = Symbol.find_first_not_of(L" \t");
        size_t End = Symbol.find_last_not_of(L" \t");

        if (Start != std::wstring::npos && End != std::wstring::npos)
            Symbol = Symbol.substr(Start, End - Start + 1);

        if (!Symbol.empty())
            Symbols.push_back(std::move(Symbol));
    }

    return Symbols;
}

std::wstring FindPdbFileByBaseName(const std::wstring& PdbPath)
{
    std::filesystem::path Path(PdbPath);
    std::wstring BaseName = Path.stem().wstring();
    std::filesystem::path Dir = Path.parent_path();

    if (Dir.empty())
        Dir = std::filesystem::current_path() / L"Symbols";

    for (const auto& entry : std::filesystem::directory_iterator(Dir))
    {
        if (entry.is_regular_file())
        {
            std::wstring fileName = entry.path().filename().wstring();

            if (fileName.size() > BaseName.size() + 1 &&
                fileName.substr(0, BaseName.size() + 1) == BaseName + L"_" &&
                _wcsicmp(fileName.substr(fileName.size() - 4).c_str(), L".pdb") == 0)
            {
                return entry.path().wstring();
            }
        }
    }

    return L"";
}

bool UpdateIniSections(const std::wstring& IniPath, const std::map<std::wstring, std::map<std::wstring, std::wstring>>& UpdatedSections)
{
    std::wstring TempPath = IniPath + L".tmp";
    std::wofstream TempFile(TempPath, std::ios::trunc);

    if (!TempFile.is_open())
    {
        printf_s("[-] Failed to create temporary file! :( Path: %ls\n", TempPath.c_str());

        return false;
    }

    std::wifstream IniFile(IniPath);

    std::set<std::wstring> ProcessedSections;
    
    std::wstring CurrentSection;

    bool bInSectionToSkip = false;
    bool bFirstSectionWritten = false;
    bool bLastLineWasSection = false;
    bool bFileExists = IniFile.is_open();

    if (bFileExists)
    {
        std::wstring Line;

        while (std::getline(IniFile, Line))
        {
            if (Line.size() > 2 && Line[0] == L'[' && Line.back() == L']')
            {
                CurrentSection = Line.substr(1, Line.size() - 2);
                bool bIsUpdatedSection = (UpdatedSections.find(CurrentSection) != UpdatedSections.end());

                if (bIsUpdatedSection)
                {
                    if (bFirstSectionWritten)
                        TempFile << L"\n";

                    TempFile << L"[" << CurrentSection << L"]\n";

                    for (const auto& [Key, Value] : UpdatedSections.at(CurrentSection))
                        TempFile << Key << L"=" << Value << L"\n";

                    bInSectionToSkip = true;
                    bFirstSectionWritten = true;
                    bLastLineWasSection = true;

                    ProcessedSections.insert(CurrentSection);

                    continue;
                }

                if (bFirstSectionWritten && !bLastLineWasSection)
                    TempFile << L"\n";

                TempFile << Line << L"\n";
                bLastLineWasSection = true;
                bInSectionToSkip = false;
            }
            else
            {
                if (!Line.empty() && !std::all_of(Line.begin(), Line.end(), iswspace))
                    bLastLineWasSection = false;

                if (bInSectionToSkip)
                    continue;

                TempFile << Line << L"\n";
            }
        }

        IniFile.close();
    }

    bool bIsAddedNewSection = false;

    for (const auto& [Section, Values] : UpdatedSections)
    {
        if (ProcessedSections.find(Section) == ProcessedSections.end())
        {
            if (bFirstSectionWritten || bIsAddedNewSection)
                TempFile << L"\n";

            TempFile << L"[" << Section << L"]\n";

            for (const auto& [Key, Value] : Values)
                TempFile << Key << L"=" << Value << L"\n";

            bIsAddedNewSection = true;
            bFirstSectionWritten = true;
        }
    }

    TempFile.close();

    if (!bFirstSectionWritten)
    {
        _wremove(TempPath.c_str());
        printf_s("[-] Nothing to write to INI file\n");

        return false;
    }

    if (!MoveFileExW(TempPath.c_str(), IniPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
    {
        DWORD Error = GetLastError();

        _wremove(TempPath.c_str());

        if (Error == ERROR_ALREADY_EXISTS)
        {
            printf_s("[!] ERROR_ALREADY_EXISTS: Attempting fallback method...\n");

            if (DeleteFileW(IniPath.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND)
            {
                if (MoveFileW(TempPath.c_str(), IniPath.c_str()))
                {
                    printf_s("[+] Successfully updated (fallback method): %ls\n", IniPath.c_str());

                    return true;
                }
            }
        }

        LPVOID lpMsgBuf;
        
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, Error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&lpMsgBuf, 0, NULL);

        printf_s("[-] Failed to replace INI file! :( Path: %ls -> %ls (Error: %lu - %ls)\n", TempPath.c_str(), IniPath.c_str(), Error, (LPWSTR)lpMsgBuf);
        LocalFree(lpMsgBuf);

        return false;
    }

    printf_s("[+] Successfully updated: %ls\n", IniPath.c_str());

    return true;
}

int wmain(int argc, wchar_t* argv[])
{
    setlocale(LC_ALL, ".UTF-8");
    printf_s("\n------\nPDB parser by Aeterts\n\n");

    if (argc < 4 || (argc - 1) % 3 != 0)
    {
        printf_s("[!] Usage: %ls \"Path_to_PDB_file1\" \"PE_file_name1\" \"Symbol1, Symbol2, ...\" \"Path_to_PDB_file2\" \"PE_file_name2\" \"Symbol1, Symbol2, ...\"...\n", argv[0]);

        return 1;
    }

    if (!SymInitializeW(GetCurrentProcess(), NULL, FALSE))
    {
        printf_s("[-] SymInitialize() failed! :( Code: %d", GetLastError());

        return 2;
    }

    DWORD SymOptions = SymGetOptions();
    SymOptions |= SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS;

    SymSetOptions(SymOptions);

    bool AllSuccess = true;
    bool bIsFirstSection = true;

    std::map<std::wstring, std::map<std::wstring, std::wstring>> UpdatedSections;

    wchar_t CurrentExePath[MAX_PATH];

    if (!GetModuleFileNameW(NULL, CurrentExePath, MAX_PATH))
    {
        wprintf_s(L"[-] GetModuleFileName failed! :( (Error: %d)\n", GetLastError());

        return -1;
    }

    for (int i = 1; i < argc; i += 3)
    {
        std::filesystem::path InputPath(argv[i]);
        std::filesystem::path PDBPath = std::filesystem::path(CurrentExePath).parent_path() / L"Symbols" / InputPath.filename();
        bool FileExists = std::filesystem::exists(InputPath);

        printf_s("[*] Processing PDB %ls file...\n", (FileExists ? InputPath.filename().c_str() : InputPath.c_str()));

        if (!FileExists && !std::filesystem::exists(PDBPath))
        {
            printf_s("[!] File not found, search for matching pattern...\n");

            PDBPath = FindPdbFileByBaseName(argv[i]);

            if (PDBPath.empty())
            {
                printf_s("[-] File not found: %ls\n\n", argv[i]);

                AllSuccess = false;

                continue;
            }

            printf_s("[+] Found matching PDB file: %ls\n", PDBPath.c_str());
        }

        std::vector<std::wstring> SymbolNames = SplitSymbols(argv[i + 2]);

        if (SymbolNames.empty())
        {
            printf_s("[-] No valid symbols for %ls\n\n", PDBPath.c_str());

            AllSuccess = false;

            continue;
        }

        DWORD FileSize = static_cast<DWORD>(std::filesystem::file_size(PDBPath.c_str()));

        DWORD64 BaseAddr = 0x40000;
        DWORD64 ModBase = SymLoadModuleExW(GetCurrentProcess(), NULL, PDBPath.c_str(), NULL, BaseAddr,
            FileSize, NULL, 0);

        if (ModBase == 0)
        {
            printf_s("[-] SymLoadModuleExW() failed! :( Code: 0x%X\n\n", GetLastError());

            AllSuccess = false;

            continue;
        }

        SYMBOL_INFO_PACKAGEW SymInfoPackage{};
        SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
        SymInfoPackage.si.MaxNameLen = sizeof(SymInfoPackage.name);

        bool bIsFileSuccess = true;
        bool bIsSectionWritten = false;

        for (const std::wstring& Sym : SymbolNames)
        {
            BOOL bRet = SymFromNameW(GetCurrentProcess(), Sym.c_str(), &SymInfoPackage.si);

            if (!bRet || !SymInfoPackage.si.Address)
            {
                printf_s("[-] Symbol '%ls' not found! :( Code: 0x%X\n\n", Sym.c_str(), GetLastError());

                bIsFileSuccess = false;

                continue;
            }

            ULONG64 Offset = SymInfoPackage.si.Address - ModBase;

            printf_s("[+] Found symbol '%ls' -> Offset: %I64u | RVA: 0x%I64x\n", Sym.c_str(),
                Offset, SymInfoPackage.si.Address);

            UpdatedSections[std::filesystem::path(argv[i + 1]).filename().c_str()][Sym] = std::to_wstring(Offset);
        }

        printf_s("\n");
        SymUnloadModule64(GetCurrentProcess(), ModBase);

        if (!bIsFileSuccess)
            AllSuccess = false;
    }

    printf_s("%s\n", UpdatedSections.empty() ? "[+] All offsets is up to date!" :
        (UpdateIniSections(std::filesystem::path(CurrentExePath).parent_path() / L"offsets.ini", UpdatedSections) ?
            "[+] All offsets saved to offsets.ini!" : "[-] Failed to update offsets.ini! :("));
    SymCleanup(GetCurrentProcess());

    int FinalResult;

    if (AllSuccess)
    {
        printf_s("[+] All symbols processed successfully!\n\n");

        FinalResult = 0;
    }
    else
    {
        printf_s("[-] Some error(s) occured during processing! :(\n\n");

        FinalResult = 3;
    }

    printf_s("------\n");

    return FinalResult;
}