Set-StrictMode -Version Latest

function script:Ensure-PsignModule {
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path (Join-Path $repoRoot 'PowerShell\Devolutions.Psign') 'Devolutions.Psign.psd1'
    Import-Module $modulePath -Force
}

Describe 'Portable file catalog cmdlets' {
    BeforeAll {
        Ensure-PsignModule
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "psign-catalog-$([System.Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Force -Path $script:TempRoot | Out-Null
    }

    AfterAll {
        if ($script:TempRoot) {
            Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeEach {
        $script:CaseRoot = Join-Path $script:TempRoot ([System.Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:CaseRoot | Out-Null
    }

    It 'creates and validates a recursive SHA256 catalog' {
        New-Item -ItemType Directory -Force -Path (Join-Path $script:CaseRoot 'sub') | Out-Null
        Set-Content -LiteralPath (Join-Path $script:CaseRoot 'a.txt') -Value 'alpha' -NoNewline -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $script:CaseRoot 'sub\b.txt') -Value 'bravo' -NoNewline -Encoding UTF8
        $catalogPath = Join-Path $script:CaseRoot 'catalog.cat'

        $created = New-PsignFileCatalog -Path $script:CaseRoot -CatalogFilePath $catalogPath
        $created | Should -BeOfType ([System.IO.FileInfo])
        $created.Exists | Should -BeTrue

        Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $script:CaseRoot -SkipTrust | Should -Be 'Valid'

        $detailed = Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $script:CaseRoot -SkipTrust -Detailed
        $detailed.HashAlgorithm | Should -Be 'SHA256'
        $detailed.CatalogItems.Path | Should -Contain 'a.txt'
        $detailed.CatalogItems.Path | Should -Contain 'sub/b.txt'
        $detailed.PathItems.Status | Should -Not -Contain 'HashMismatch'
        $detailed.Signature.Status | Should -Be 'NotSigned'
    }

    It 'reports tampered files and honors FilesToSkip' {
        Set-Content -LiteralPath (Join-Path $script:CaseRoot 'a.txt') -Value 'alpha' -NoNewline -Encoding UTF8
        $catalogPath = Join-Path $script:CaseRoot 'catalog.cat'
        New-PsignFileCatalog -Path $script:CaseRoot -CatalogFilePath $catalogPath | Out-Null
        Set-Content -LiteralPath (Join-Path $script:CaseRoot 'a.txt') -Value 'tampered' -NoNewline -Encoding UTF8

        Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $script:CaseRoot -SkipTrust | Should -Be 'ValidationFailed'
        $detailed = Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $script:CaseRoot -SkipTrust -Detailed
        ($detailed.PathItems | Where-Object Path -EQ 'a.txt').Status | Should -Be 'HashMismatch'

        Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $script:CaseRoot -SkipTrust -FilesToSkip 'a.txt' | Should -Be 'Valid'
    }

    It 'rejects duplicate filenames for multiple unrelated paths' {
        $left = Join-Path $script:CaseRoot 'left'
        $right = Join-Path $script:CaseRoot 'right'
        New-Item -ItemType Directory -Force -Path $left, $right | Out-Null
        Set-Content -LiteralPath (Join-Path $left 'same.txt') -Value 'left' -NoNewline -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $right 'same.txt') -Value 'right' -NoNewline -Encoding UTF8

        { New-PsignFileCatalog -Path $left, $right -CatalogFilePath (Join-Path $script:CaseRoot 'catalog.cat') -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*duplicate subject file name*'
    }

    It 'supports WhatIf without creating a catalog' {
        Set-Content -LiteralPath (Join-Path $script:CaseRoot 'a.txt') -Value 'alpha' -NoNewline -Encoding UTF8
        $catalogPath = Join-Path $script:CaseRoot 'catalog.cat'

        New-PsignFileCatalog -Path $script:CaseRoot -CatalogFilePath $catalogPath -WhatIf

        Test-Path -LiteralPath $catalogPath | Should -BeFalse
    }

    It 'reports the embedded signature status for signed catalog fixtures' {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $catalogPath = Join-Path $repoRoot 'tests\fixtures\generated-signed\catalog\sample.cat'
        $memberPath = Join-Path $repoRoot 'tests\fixtures\generated-unsigned\catalog\member.sys'

        $detailed = Test-PsignFileCatalog -CatalogFilePath $catalogPath -Path $memberPath -SkipTrust -Detailed

        $detailed.Signature.Status | Should -Be 'Valid'
        $detailed.Signature.SignatureType | Should -Be ([System.Management.Automation.SignatureType]::Catalog)
    }
}
