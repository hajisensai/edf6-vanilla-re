param(
    [Parameter(Mandatory)][string]$Game,
    [Parameter(Mandatory)][string]$Ghidra,
    [string]$Java = 'java.exe',
    [ValidateSet('EDF.dll', 'EDF6.exe')][string]$Module = 'EDF.dll',
    [ValidateRange(1, 64)][int]$Workers = 6,
    [string]$Output,
    [string]$AddressList,
    [ValidateRange(1, 900)][int]$TimeoutSeconds,
    [ValidateSet('decompile', 'normalize', 'firstpass')][string]$Simplification = 'decompile',
    [switch]$ReuseProject,
    [switch]$Unwind,
    [switch]$RetryFailed,
    [switch]$SeedCandidates,
    [switch]$AllowUnofficial,
    [switch]$NoSharedLabels,
    # Import and auto-analyze only; export later with -ReuseProject.
    [switch]$ImportOnly,
    # 0 = no limit. Passed to Ghidra as -analysisTimeoutPerFile.
    [ValidateRange(0, 604800)][int]$AnalysisTimeoutSeconds = 0,
    # Instruction-level P-code: pairs of annotated .asm inputs and new .pcode outputs (needs -ReuseProject).
    [string[]]$IrInput,
    [string[]]$IrOutput,
    # Artifact root (default: $env:EDF6RE_OUT, else <repo>/out) and an optional Ghidra log path.
    [string]$OutRoot,
    [string]$Log,
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
if (-not $OutRoot) { $OutRoot = if ($env:EDF6RE_OUT) { $env:EDF6RE_OUT } else { Join-Path $PSScriptRoot 'out' } }
$outRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutRoot)
$cacheDirectory = Join-Path $outRoot '_cache'
$projectDirectory = Join-Path $cacheDirectory 'projects'
$projectName = if ($Module -eq 'EDF.dll') { 'game' } else { 'launcher' }
$baseProject = $projectName
# powershell -File passes an array as one comma-joined string; split it back.
$IrInput = @($IrInput | Where-Object { $_ } | ForEach-Object { $_ -split ',' })
$IrOutput = @($IrOutput | Where-Object { $_ } | ForEach-Object { $_ -split ',' })
$instructionIR = [bool]($IrInput.Count -or $IrOutput.Count)
if ((@($Unwind, $RetryFailed, $SeedCandidates, $ImportOnly, $instructionIR) | Where-Object { $_ }).Count -gt 1) {
    throw 'Choose one of -Unwind, -RetryFailed, -SeedCandidates, -ImportOnly and -IrInput/-IrOutput.'
}
if ($instructionIR) {
    if (-not $ReuseProject) { throw 'Use -IrInput/-IrOutput with -ReuseProject.' }
    if (@($IrInput).Count -ne @($IrOutput).Count) { throw '-IrInput and -IrOutput need the same number of paths.' }
}
if ($ImportOnly -and $ReuseProject) { throw 'Use -ImportOnly without -ReuseProject.' }
if ($AddressList -and -not ($RetryFailed -or $SeedCandidates)) { throw 'Use -AddressList with -RetryFailed or -SeedCandidates.' }
if ($SeedCandidates -and -not ($AddressList -and $ReuseProject)) { throw 'Use -SeedCandidates with -AddressList and -ReuseProject.' }
if ($Unwind) {
    if (-not $ReuseProject) { throw 'Use -Unwind with -ReuseProject.' }
    $projectName += '-unwind'
}
$logName = if ($ImportOnly) { "$projectName-import.log" } elseif ($instructionIR) { "$projectName-pcode.log" } elseif ($RetryFailed) { "$projectName-retry.log" } elseif ($SeedCandidates) { "$projectName-candidates.log" } else { "$projectName-export.log" }
if (-not $Log) { $Log = Join-Path $cacheDirectory $logName }
$Log = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Log)
if (-not $Output) {
    $Output = Join-Path $outRoot $(if ($Unwind) { 'pseudocode-unwind' } elseif ($RetryFailed) { 'pseudocode-retry' } elseif ($SeedCandidates) { 'pseudocode-candidates' } else { 'pseudocode' })
}
$gameDirectory = (Resolve-Path -LiteralPath $Game).Path
$ghidraDirectory = (Resolve-Path -LiteralPath $Ghidra).Path
$sourceImage = (Resolve-Path -LiteralPath (Join-Path $gameDirectory $Module)).Path
$sourceHash = (Get-FileHash -LiteralPath $sourceImage -Algorithm SHA256).Hash
$jar = (Resolve-Path -LiteralPath (Join-Path $ghidraDirectory 'Ghidra/Framework/Utility/lib/Utility.jar')).Path
$outputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$completion = Join-Path (Join-Path $outputDirectory $Module) 'complete.txt'
if (-not ($ImportOnly -or $instructionIR) -and (Test-Path -LiteralPath (Join-Path $outputDirectory $Module))) {
    throw "Output already exists. Use -Output to export into a new directory."
}
if ($instructionIR) {
    foreach ($path in $IrOutput) { if (Test-Path -LiteralPath $path) { throw "P-code output already exists: $path" } }
}
New-Item -ItemType Directory -Path $projectDirectory -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $Log) -Force | Out-Null
$rvaList = Join-Path $PSScriptRoot 'priority-rvas.txt'
if ($SeedCandidates) { $rvaList = (Resolve-Path -LiteralPath $AddressList).Path }
if ($RetryFailed) {
    if (-not $ReuseProject) { throw 'Use -RetryFailed with -ReuseProject.' }
    if ($AddressList) {
        $rvaList = (Resolve-Path -LiteralPath $AddressList).Path
    } else {
        $index = Join-Path $outRoot "pseudocode/$Module/functions.tsv"
        $failedRvas = @(Import-Csv -LiteralPath $index -Delimiter "`t" | Where-Object status -eq 'failed' | ForEach-Object rva)
        if ($failedRvas.Count -eq 0) { throw "No failed functions listed in $index" }
        $rvaList = Join-Path $cacheDirectory "$projectName-retry-rvas.txt"
        $failedRvas | Set-Content -LiteralPath $rvaList -Encoding ascii
    }
}
if ($Unwind -and -not (Test-Path -LiteralPath (Join-Path $projectDirectory "$projectName.gpr"))) {
    $baseData = Join-Path $projectDirectory "$baseProject.rep"
    $baseMarker = Join-Path $projectDirectory "$baseProject.gpr"
    if (-not (Test-Path -LiteralPath $baseMarker)) { throw "No analyzed project $baseProject." }
    Copy-Item -LiteralPath $baseData -Destination (Join-Path $projectDirectory "$projectName.rep") -Recurse
    Copy-Item -LiteralPath $baseMarker -Destination (Join-Path $projectDirectory "$projectName.gpr")
}

$sourceArgs = if ($ReuseProject) {
    @('-process', $Module, '-noanalysis', '-readOnly')
} else {
    if (Test-Path -LiteralPath (Join-Path $projectDirectory "$projectName.gpr")) {
        throw "Project $projectName already exists. Use -ReuseProject to export it."
    }
    @('-import', $sourceImage)
}
if ($AnalysisTimeoutSeconds -and -not $ReuseProject) { $sourceArgs += @('-analysisTimeoutPerFile', $AnalysisTimeoutSeconds) }

# Provenance gate: stop unless $Module is a verified official build (or -AllowUnofficial, which is recorded).
$provenance = Join-Path $cacheDirectory "provenance-$projectName.json"
$verifyArgs = @('-B', (Join-Path $PSScriptRoot 'verify_install.py'), $gameDirectory, '--quick', '--module', $Module, '--json', $provenance)
if ($AllowUnofficial) { $verifyArgs += '--allow-unofficial' }
& $Python @verifyArgs
if ($LASTEXITCODE -and -not $AllowUnofficial) { Remove-Item -LiteralPath $provenance -ErrorAction SilentlyContinue; throw "verify_install.py exited $LASTEXITCODE`: $Module is not a verified official build (use -AllowUnofficial to override)." }
if ($ImportOnly -or $instructionIR) {
    Move-Item -LiteralPath $provenance -Destination (Join-Path $cacheDirectory "provenance-$projectName-$(if ($ImportOnly) { 'import' } else { 'pcode' }).json") -Force
} else {
    New-Item -ItemType Directory -Path (Join-Path $outputDirectory $Module) -Force | Out-Null
    Move-Item -LiteralPath $provenance -Destination (Join-Path (Join-Path $outputDirectory $Module) 'provenance.json') -Force
}

$javaArgs = @(
    '-Xmx4g', "-XX:ActiveProcessorCount=$Workers"
)
if ($TimeoutSeconds) { $javaArgs += "-Dedf6.export.timeout=$TimeoutSeconds" }
if ($Simplification -ne 'decompile') { $javaArgs += "-Dedf6.export.simplification=$Simplification" }
$javaArgs += @(
    '-Dfile.encoding=UTF-8',
    "-Dedf6.export.sha256=$sourceHash",
    '-Djava.system.class.loader=ghidra.GhidraClassLoader',
    "-Dapplication.settingsdir=$cacheDirectory/settings-$projectName",
    "-Dapplication.cachedir=$cacheDirectory/cache", "-Dapplication.tempdir=$cacheDirectory/tmp",
    '-cp', $jar, 'ghidra.GhidraLauncher', 'ghidra.app.util.headless.AnalyzeHeadless',
    $projectDirectory, $projectName
) + $sourceArgs + @(
    '-max-cpu', $Workers, '-scriptPath', (Join-Path $PSScriptRoot 'ghidra_scripts'), '-log', $Log
)
if ($instructionIR) {
    for ($i = 0; $i -lt @($IrInput).Count; $i++) {
        $source = (Resolve-Path -LiteralPath @($IrInput)[$i]).Path
        $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(@($IrOutput)[$i])
        $javaArgs += @('-postScript', 'ExportInstructionIR.java', $source, $target)
    }
    & $Java @javaArgs
    if ($LASTEXITCODE) { throw "Ghidra P-code export exited $LASTEXITCODE. Check $Log" }
    foreach ($path in $IrOutput) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Ghidra P-code export did not write $path. Check $Log" }
    }
    return
}
# Shared labels go in before the export so pseudocode and indexes use the community names.
# With -ReuseProject (-readOnly) they apply to this run only; a fresh import saves them in the project.
if (-not $NoSharedLabels) {
    $javaArgs += @('-postScript', 'ImportSharedLabels.java', (Join-Path $PSScriptRoot 'shared'))
}
if ($ImportOnly) {
    & $Java @javaArgs
    $text = if (Test-Path -LiteralPath $Log) { Get-Content -LiteralPath $Log -Raw } else { '' }
    if ($LASTEXITCODE -or $text -notmatch 'REPORT: Import succeeded' -or -not (Test-Path -LiteralPath (Join-Path $projectDirectory "$projectName.gpr"))) {
        throw "Ghidra import did not succeed. Check $Log"
    }
    if ($text -match 'Analysis timed out at (\d+) seconds') { "analysis_timed_out_seconds=$($Matches[1])" }
    "import=ok project=$projectName"
    return
}
$javaArgs += @('-postScript', 'ExportVanilla.java', $outputDirectory, $rvaList)
if ($Unwind) { $javaArgs += 'unwind' }
if ($RetryFailed) { $javaArgs += 'retry' }
if ($SeedCandidates) { $javaArgs += 'candidates' }
& $Java @javaArgs
if ($LASTEXITCODE -or -not (Test-Path -LiteralPath $completion)) {
    throw "Ghidra export did not reach completion. Check $Log"
}
Get-Content -LiteralPath $completion
