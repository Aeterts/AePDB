### **AePDB**
A toolkit for working with PDB files (Program Database), used in Windows for debugging and symbolic analysis of binary files. Consists of three utilities that enable downloading, parsing, and updating symbols for PE files.

---

#### **Contents**
1. **AePDBDownloader**
   - **Purpose**: Downloads PDB files from Microsoft Symbols Server (`http://msdl.microsoft.com/download/symbols`).
   - **How it works**:
     - Extracts PDB information (GUID, age, filename) from a PE file.
     - Constructs a download URL using the template `http://msdl.microsoft.com/download/symbols/<filename>/<guid+age>/<filename>`.
     - Saves the result to the `Symbols/` folder.
   - **Example usage**:
     ```bash
     AePDBDownloader.exe "C:\path\to\binary.exe"
     ```

2. **AePDBParser**
   - **Purpose**: Parses PDB files and extracts symbol addresses (functions, variables).
   - **How it works**:
     - Uses the `DbgHelp` API to load symbols.
     - Searches for specified symbols in the `Symbols/.pbd` (supports absolute and relative path) and writes their offset to `offsets.ini`.
   - **Example usage**:
     ```bash
     AePDBParser.exe "binary.pdb" "binary.exe" "Function1, Function2"
     ```

3. **AePDBUpdater**
   - **Purpose**: Automates the process of checking and updating PDB files.
   - **How it works**:
     - Verifies the validity of existing PDB files.
     - Launches `AePDBDownloader` and `AePDBParser` when necessary.
     - Removes outdated PDB versions.
   - **Example usage**:
     ```bash
     AePDBUpdater.exe "binary.exe" "Symbol1, Symbol2"
     ```

---

#### **Requirements**
- Operating System: Windows (uses Win32 and DbgHelp APIs).
- Libraries:
  - `urlmon.lib` (for HTTP file downloads).
  - `dbghelp.lib` (for symbol handling).
- Build tools: Visual Studio or another C++ compiler supporting C++20.

---

#### **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo.git
   ```
2. Open the solution in Visual Studio (`AePDB.sln`) and build the project.
3. Copy/move DLLs to build folder.
---

#### **Usage**
1. **Download PDB**:
   ```bash
   AePDBDownloader.exe "path_to_binary_file"
   ```
2. **Parse Symbols**:
   ```bash
   AePDBParser.exe "path_to_pdb_file" "binary_filename" "symbol1, symbol2"
   ```
3. **Update Symbols**:
   ```bash
   AePDBUpdater.exe "path_to_binary_file" "symbol1, symbol2"
   ```

---

#### **Notes**
- An internet connection is required for remote symbol operations.
- Some operations (e.g., writing to system directories) may require administrator privileges.
- Parsing results are saved to `offsets.ini` in the current directory.
- Not every PE files can provide PDB or not any PDB could be downloaded

---

#### **License**
This project is licensed under the [MIT License](LICENSE). Use it freely, but retain the author attribution.
