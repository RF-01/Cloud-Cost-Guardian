# Launch guardrail tests (design §8.7, task #25). Every call uses --dry-run:
# nothing is created and nothing is billed.
#
#   powershell -File infra\shared\tests\guardrail-dryrun.ps1 -Expect before   # guardrails not applied yet
#   powershell -File infra\shared\tests\guardrail-dryrun.ps1 -Expect after    # after terraform apply
#
# Temp tag JSON files go to $env:TEMP\cg-guardrail-tests\, so the repo stays clean.
#
# Result per call: ALLOWED (DryRunOperation), REFUSED (UnauthorizedOperation), ERROR (anything else).
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('before', 'after')]
    [string]$Expect
)

$ErrorActionPreference = 'Continue'
$Profile_ = 'guardian'
$Region   = 'us-west-2'
$Subnet   = 'subnet-02ac2f5aba3a63b76'   # us-west-2a
$Az       = 'us-west-2a'
$Owner    = 'rif07@mail.aub.edu'
$Project  = 'cost-guardian'
$Dir      = Join-Path $env:TEMP 'cg-guardrail-tests'
if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Invoke-Aws {
    # Runs the AWS CLI and returns its combined output as one string (no ErrorRecord wrapping).
    param([string[]]$CliArgs)
    $lines = & aws @CliArgs --profile $Profile_ --region $Region 2>&1 | ForEach-Object { "$_" }
    return ($lines -join "`n")
}

function Write-TagFile {
    # Writes a --tag-specifications JSON file (UTF-8 without BOM) and returns its file:// URI.
    param([string]$Name, [object[]]$Specs)
    $path = Join-Path $Dir "tags-$Name.json"
    $json = ConvertTo-Json -InputObject @($Specs) -Depth 5
    [IO.File]::WriteAllText($path, $json, $Utf8NoBom)
    return 'file://' + ($path -replace '\\', '/')
}

function New-Spec {
    param([string]$ResourceType, [hashtable]$Tags)
    $list = @()
    foreach ($k in ($Tags.Keys | Sort-Object)) { $list += [ordered]@{ Key = $k; Value = $Tags[$k] } }
    return [ordered]@{ ResourceType = $ResourceType; Tags = $list }
}

function Get-Outcome {
    param([string]$Output)
    if ($Output -match 'DryRunOperation') { return @{ Result = 'ALLOWED'; Detail = '' } }
    if ($Output -match 'UnauthorizedOperation') {
        $detail = ''
        if ($Output -match 'Encoded authorization failure message:\s*(\S+)') {
            $encoded = $Matches[1]
            $decodedRaw = Invoke-Aws @('sts', 'decode-authorization-message', "--encoded-message=$encoded",
                                       '--query', 'DecodedMessage', '--output', 'text')
            try {
                $d = $decodedRaw | ConvertFrom-Json
                $sids = @($d.matchedStatements.items | ForEach-Object { $_.statementId }) -join ','
                $detail = "sid=$sids explicitDeny=$($d.explicitDeny)"
            } catch {
                $detail = 'could not decode: ' + $decodedRaw.Substring(0, [Math]::Min(120, $decodedRaw.Length))
            }
        }
        return @{ Result = 'REFUSED'; Detail = $detail }
    }
    $first = ($Output -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    return @{ Result = 'ERROR'; Detail = $first }
}

# --- Identity -------------------------------------------------------------
Write-Host '== Caller identity'
$ident = Invoke-Aws @('sts', 'get-caller-identity', '--output', 'json')
Write-Host $ident
if ($ident -notmatch ':user/reda"') {
    Write-Host 'Caller is not IAM user reda: stopping.'
    exit 2
}

# --- AMI ------------------------------------------------------------------
$Ami = (Invoke-Aws @('ssm', 'get-parameter', '--name',
        '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
        '--query', 'Parameter.Value', '--output', 'text')).Trim()
if ($Ami -notmatch '^ami-[0-9a-f]+$') { Write-Host "Could not read the AL2023 AMI: $Ami"; exit 2 }
Write-Host "== AMI $Ami, subnet $Subnet ($Az), expect '$Expect'"

# --- Tag files ------------------------------------------------------------
$full      = @{ owner = $Owner; project = $Project }
$badOwner  = @{ owner = 'not-an-email'; project = $Project }
$ownerOnly = @{ owner = $Owner }

$tFull      = Write-TagFile 'full'       @((New-Spec 'instance' $full), (New-Spec 'volume' $full))
$tInstOnly  = Write-TagFile 'inst-only'  @((New-Spec 'instance' $full))
$tBadOwner  = Write-TagFile 'bad-owner'  @((New-Spec 'instance' $badOwner), (New-Spec 'volume' $badOwner))
$tOwnerOnly = Write-TagFile 'owner-only' @((New-Spec 'instance' $ownerOnly), (New-Spec 'volume' $ownerOnly))
$tVolume    = Write-TagFile 'volume'     @((New-Spec 'volume' $full))
$tEip       = Write-TagFile 'eip'        @((New-Spec 'elastic-ip' $full))

function RunArgs([string]$Type, [string]$TagUri) {
    $a = @('ec2', 'run-instances', '--dry-run', '--image-id', $Ami, '--instance-type', $Type,
           '--subnet-id', $Subnet, '--count', '1')
    if ($TagUri) { $a += @('--tag-specifications', $TagUri) }
    return , $a
}
$volArgs = @('ec2', 'create-volume', '--dry-run', '--availability-zone', $Az, '--size', '1', '--volume-type', 'gp3')
$eipArgs = @('ec2', 'allocate-address', '--dry-run', '--domain', 'vpc')

# --- Cases: id, description, CLI args, expected result after apply ------
$cases = @(
    @{ Id = '1';  Desc = 'run t3.micro, tags on instance + volume';   Args = (RunArgs 't3.micro' $tFull);      After = 'ALLOWED' },
    @{ Id = '2';  Desc = 'run t3.micro, no tags';                      Args = (RunArgs 't3.micro' $null);       After = 'REFUSED' },
    @{ Id = '3';  Desc = 'run t3.micro, tags on instance only';        Args = (RunArgs 't3.micro' $tInstOnly);  After = 'REFUSED' },
    @{ Id = '4';  Desc = 'run m5.large, full tags';                    Args = (RunArgs 'm5.large' $tFull);      After = 'REFUSED' },
    @{ Id = '5a'; Desc = 'create-volume 1 GiB gp3, tags';              Args = ($volArgs + @('--tag-specifications', $tVolume)); After = 'ALLOWED' },
    @{ Id = '5b'; Desc = 'create-volume 1 GiB gp3, no tags';           Args = $volArgs;                         After = 'REFUSED' },
    @{ Id = '5c'; Desc = 'allocate-address vpc, tags';                 Args = ($eipArgs + @('--tag-specifications', $tEip)); After = 'ALLOWED' },
    @{ Id = '5d'; Desc = 'allocate-address vpc, no tags';              Args = $eipArgs;                         After = 'REFUSED' },
    @{ Id = '6';  Desc = 'run t3.micro, owner=not-an-email';           Args = (RunArgs 't3.micro' $tBadOwner);  After = 'REFUSED' },
    @{ Id = '7';  Desc = 'run t3.micro, owner only (no project)';      Args = (RunArgs 't3.micro' $tOwnerOnly); After = 'REFUSED' }
)

$rows = @()
$failed = 0
foreach ($c in $cases) {
    $expected = if ($Expect -eq 'before') { 'ALLOWED' } else { $c.After }
    $o = Get-Outcome (Invoke-Aws $c.Args)
    $ok = ($o.Result -eq $expected)
    if (-not $ok) { $failed++ }
    $rows += [pscustomobject]@{
        Case     = $c.Id
        Test     = $c.Desc
        Expected = $expected
        Got      = $o.Result
        Status   = $(if ($ok) { 'PASS' } else { 'FAIL' })
        Detail   = $o.Detail
    }
}

$rows | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
if ($failed -gt 0) { Write-Host "$failed case(s) FAILED"; exit 1 }
Write-Host 'All cases PASS'
exit 0
