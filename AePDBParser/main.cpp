#include <Windows.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <sstream>

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

    std::wstring OffsetsPath = L"offsets.ini";
    FILE* OffsetsFile = nullptr;
    
    _wfopen_s(&OffsetsFile, OffsetsPath.c_str(), L"wt, ccs=UTF-8");

    if (OffsetsFile)
    {
        printf_s("[*] Writing offsets to: %ls\n", OffsetsPath.c_str());
    }
    else
    {
        printf_s("[-] Failed to create config file: %ls (Error: %d)\n", OffsetsPath.c_str(), GetLastError());
    }

    for (int i = 1; i < argc; i += 3)
    {
        std::filesystem::path InputPath(argv[i]);
        std::filesystem::path PDBPath = std::filesystem::current_path() / "Symbols" / InputPath.filename();
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

            if (!OffsetsFile)
                continue;

            if (!bIsSectionWritten)
            {
                if (!bIsFirstSection)
                    fwprintf_s(OffsetsFile, L"\n");

                fwprintf(OffsetsFile, L"[%ls]\n", std::filesystem::path(argv[i + 1]).filename().c_str());

                bIsSectionWritten = true;
                bIsFirstSection = false;
            }

            fwprintf(OffsetsFile, L"%ls=%I64u\n", Sym.c_str(), Offset);
        }

        printf_s("\n");
        SymUnloadModule64(GetCurrentProcess(), ModBase);

        if (!bIsFileSuccess)
            AllSuccess = false;
    }

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