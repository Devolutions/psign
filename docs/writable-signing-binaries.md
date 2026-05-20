# Writable copies of native signing binaries

Some workflows need a **writable directory** next to **`signtool.exe`**, **`mssign32.dll`**, or **`WINTRUST.dll`**. Files under **`Program Files (x86)\Windows Kits\...`** and **`%SystemRoot%\System32`** are often **read-only** for normal users, so tools that create sidecar files next to the input may fail with access denied.

## Automation

From the repo root on Windows:

```powershell
pwsh -File scripts/prepare-writable-signing-binaries.ps1
```

This recreates **`parity-output/writable-signing-binaries/`** (gitignored with the rest of **`parity-output/`**) with:

- **`WINTRUST.dll`**, **`mssign32.dll`** from **`%SystemRoot%\System32`**
- **`signtool.exe`** and the matching Kits **`mssign32.dll`** from the newest **`Windows Kits\10\bin\<version>\x64\`** under **`Program Files (x86)`**

Copy any additional vendor DLLs you need (for example decoupled digest drivers) into the same folder manually.

## How this ties into the repo

Product and parity context: [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md), [`linux-signing-pipelines.md`](linux-signing-pipelines.md), and the Windows parity scripts under **`scripts/`**. Prefer **`psign`** sources, fixtures, and public Microsoft documentation when reasoning about behavior.
