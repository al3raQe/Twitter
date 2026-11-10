param([string]$IPA, [string]$Output)
$ErrorActionPreference = 'Stop'
try {
    if (-not $IPA) {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = 'Select a decrypted Twitter/X IPA'
        $dialog.Filter = 'IPA files (*.ipa)|*.ipa'
        $dialog.InitialDirectory = Join-Path $PSScriptRoot 'input'
        if ($dialog.ShowDialog() -ne 'OK') { exit 0 }
        $IPA = $dialog.FileName
        $dialog.Dispose()
    }
    $python = Join-Path $PSScriptRoot '.tools/python/python.exe'
    $script = Join-Path $PSScriptRoot 'tools/merge_ipa.py'
    $arguments = @($script, '--input', (Resolve-Path -LiteralPath $IPA).Path)
    if ($Output) { $arguments += @('--output', $Output) }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'IPA assembly failed. See the error above.' }
    Write-Host 'Done. Open the resulting IPA in Sideloadly to sign and install it.' -ForegroundColor Green
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
