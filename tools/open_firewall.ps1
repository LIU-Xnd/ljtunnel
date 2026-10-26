# Open the ports ljtunnel needs.
#
# Run this ONCE, in a terminal that is running as Administrator:
#
#     powershell -ExecutionPolicy Bypass -File open_firewall.ps1
#
# The listen end's sshd has to be reachable from the network, and
# Windows blocks inbound traffic to a port it has not been told about.
# The block is SILENT: the dialer times out with no message at all.
#
# The rule is for the sshd program as well as the ports, so it does
# not go stale when the program moves, and so it can be taken away
# with:
#
#     netsh advfirewall firewall delete rule name="ljtunnel inbound"

$ErrorActionPreference = "Stop"

$ruleName = "ljtunnel inbound"
$sshd     = "$env:ProgramFiles\OpenSSH\sshd.exe"
$ports    = "10001,10002-10021"

if (-not (Test-Path $sshd)) {
    Write-Warning "sshd.exe is not at $sshd -- the rule will not match it."
    Write-Warning "Install OpenSSH for Windows, or point the rule at the real path."
}

# Remove an older copy first, so running this twice does not leave
# two rules behind.
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "removing the old rule ..."
    Remove-NetFirewallRule -DisplayName $ruleName
}

Write-Host "adding the rule for ports $ports ..."
New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $ports `
    -Program $sshd `
    -Profile Any `
    -Enabled True | Out-Null

Write-Host ""
Write-Host "the rule is in:"
Get-NetFirewallRule -DisplayName $ruleName |
    Select-Object DisplayName, Direction, Action, Enabled, Profile |
    Format-Table -AutoSize
