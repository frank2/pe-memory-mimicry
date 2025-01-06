param([string]$Filename,
      [string]$Label,
      [string]$Output)

$filesize = (Get-Item $Filename | Select-Object Length).Length;
Write-Output "#pragma once`n#define $Label $filesize" | Out-File $Output
