$Sizes = @{
    "1KiB" = 1024
    "4KiB" = 4096
    "16KiB" = 16384
    "256KiB" = 262144
    "1MiB" = 1048576
    "8MiB" = 8388608
}

$AESTool = ".\build\Debug\aestool.exe"
$Runs = 30

New-Item -ItemType Directory -Force -Path "benchmarks" | Out-Null

foreach ($Size in $Sizes.GetEnumerator()) {
    $Name = $Size.Name
    $Bytes = $Size.Value
    $Payload = "benchmarks\payload_$Name.bin"
    $CsvOut = "benchmarks\benchmark_$Name.csv"
    
    Write-Host "Generating $Payload ($Bytes bytes)..."
    $Data = New-Object byte[] $Bytes
    $Rand = New-Object System.Random
    $Rand.NextBytes($Data)
    [System.IO.File]::WriteAllBytes((Resolve-Path -Path ".\" | Select-Object -ExpandProperty Path) + "\$Payload", $Data)

    Write-Host "Running benchmarks for $Name..."
    & $AESTool bench --in $Payload --out $CsvOut --runs $Runs
    
    Write-Host "Finished $Name. Data saved to $CsvOut."
    Write-Host "------------------------------------------------"
}

Write-Host "All benchmarks completed! Check the 'benchmarks' folder for CSV files."
