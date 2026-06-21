$Sizes = @{
    "1MiB" = 1048576
    "100MiB" = 104857600
}

$AESTool = ".\build\Release\aestool2.exe"
$Runs = 30

New-Item -ItemType Directory -Force -Path "benchmarks" | Out-Null

foreach ($Size in $Sizes.GetEnumerator()) {
    $Name = $Size.Name
    $Bytes = $Size.Value
    $Payload = "benchmarks\payload_$Name.bin"
    $CsvOut = "benchmarks\benchmark_$Name.csv"
    
    if (-not (Test-Path $Payload)) {
        Write-Host "Generating $Payload ($Bytes bytes)..."
        $Data = New-Object byte[] $Bytes
        $Rand = New-Object System.Random
        $Rand.NextBytes($Data)
        [System.IO.File]::WriteAllBytes((Resolve-Path -Path ".\" | Select-Object -ExpandProperty Path) + "\$Payload", $Data)
    }

    Write-Host "Running benchmarks for $Name..."
    & $AESTool bench --in $Payload --out $CsvOut --runs $Runs
    
    Write-Host "Finished $Name. Data saved to $CsvOut."
    Write-Host "------------------------------------------------"
}

Write-Host "All benchmarks completed! Check the 'benchmarks' folder for CSV files."
