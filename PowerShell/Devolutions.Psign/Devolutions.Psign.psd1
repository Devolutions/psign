@{
    RootModule = 'Devolutions.Psign.psm1'
    ModuleVersion = '0.3.0'
    GUID = 'e6e50e4b-bf25-4ed6-a343-49f904e79f8f'
    Author = 'Devolutions'
    CompanyName = 'Devolutions'
    Copyright = '(c) Devolutions. All rights reserved.'
    Description = 'Portable Authenticode signing and inspection cmdlets backed by psign.'
    CompatiblePSEditions = @('Core')
    PowerShellVersion = '7.4'
    NestedModules = @('lib/net8.0/Devolutions.Psign.PowerShell.dll')
    FormatsToProcess = @('Devolutions.Psign.Format.ps1xml')
    CmdletsToExport = @(
        'Get-PortableSignature',
        'Set-PortableSignature',
        'Test-PsignModule',
        'Protect-PsignModule',
        'Unprotect-PsignSignature'
    )
    FunctionsToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Authenticode', 'CodeSigning', 'Portable', 'psign')
            LicenseUri = 'https://github.com/Devolutions/psign/blob/master/LICENSE'
            ProjectUri = 'https://github.com/Devolutions/psign'
        }
    }
}
