# Binary cmdlets are loaded through the module manifest's NestedModules entry.

# Argument completers for common parameters

Register-ArgumentCompleter -CommandName Set-PortableSignature, Protect-PsignModule -ParameterName Thumbprint -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $baseDir = if ($fakeBoundParameters.ContainsKey('CertStoreDirectory')) {
        $fakeBoundParameters['CertStoreDirectory']
    } elseif ($env:PSIGN_CERT_STORE) {
        $env:PSIGN_CERT_STORE
    } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.psign' 'cert-store'
    }
    $scope = if ($fakeBoundParameters.ContainsKey('MachineStore') -and $fakeBoundParameters['MachineStore']) { 'LocalMachine' } else { 'CurrentUser' }
    $store = if ($fakeBoundParameters.ContainsKey('StoreName')) { $fakeBoundParameters['StoreName'] } else { 'MY' }
    $storeDir = Join-Path $baseDir $scope $store
    if (Test-Path $storeDir) {
        Get-ChildItem -Path $storeDir -Filter '*.der' | ForEach-Object {
            $thumb = $_.BaseName
            if ($thumb -like "$wordToComplete*") {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)
                $subject = $cert.Subject -replace '^CN=','' -replace ',.*$',''
                $cert.Dispose()
                [System.Management.Automation.CompletionResult]::new(
                    $thumb, "$thumb ($subject)", 'ParameterValue', $subject)
            }
        }
    }
}

Register-ArgumentCompleter -CommandName Set-PortableSignature, Protect-PsignModule -ParameterName StoreName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('MY', 'Root', 'CA', 'Trust', 'Disallowed') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

Register-ArgumentCompleter -CommandName Set-PortableSignature, Protect-PsignModule -ParameterName HashAlgorithm -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Sha256', 'Sha384', 'Sha512') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

Register-ArgumentCompleter -CommandName Get-PortableSignature -ParameterName RevocationMode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Off', 'BestEffort', 'Require') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

Register-ArgumentCompleter -CommandName Test-PsignModule -ParameterName Policy -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('AllSigned', 'RemoteSigned') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
