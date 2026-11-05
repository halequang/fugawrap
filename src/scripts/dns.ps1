# Switch the active adapter's DNS to a provider with DNS-over-HTTPS, or restore it.
# The app prepends: $Mode = 'set' | 'restore'; $Provider = '<key>'.
# Exit codes: 0 ok, 2 no adapter, 3 nothing to restore, 4 state belongs to another adapter.
$ErrorActionPreference = 'Continue'
$Dir   = Join-Path $env:ProgramData 'NetFix'
$State = Join-Path $Dir 'dns-state.json'
$Log   = Join-Path $Dir 'dns.log'

# ProgramData subfolders inherit write access for every local user. The state file
# decides what gets restored as administrator, so only admins and SYSTEM may write.
if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
icacls $Dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

function L($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Mode] $m" | Out-File -FilePath $Log -Append -Encoding utf8 }

# Providers that send EDNS Client Subnet get CDN answers near the user. On networks
# where only far-away CDN nodes are blocked, that alone fixes access.
$Providers = @{
    google     = @{ v4 = @('8.8.8.8', '8.8.4.4');           v6 = @('2001:4860:4860::8888', '2001:4860:4860::8844'); doh = 'https://dns.google/dns-query' }
    opendns    = @{ v4 = @('208.67.222.222', '208.67.220.220'); v6 = @('2620:119:35::35', '2620:119:53::53');       doh = 'https://doh.opendns.com/dns-query' }
    adguard    = @{ v4 = @('94.140.14.14', '94.140.15.15');  v6 = @('2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff');     doh = 'https://dns.adguard-dns.com/dns-query' }
    alibaba    = @{ v4 = @('223.5.5.5', '223.6.6.6');        v6 = @('2400:3200::1', '2400:3200:baba::1');         doh = 'https://dns.alidns.com/dns-query' }
    cloudflare = @{ v4 = @('1.1.1.1', '1.0.0.1');            v6 = @('2606:4700:4700::1111', '2606:4700:4700::1001'); doh = 'https://cloudflare-dns.com/dns-query' }
}

function Doh-Base($guid) {
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings"
}

# The adapter that owns the best default route, not just the first one that is up
# (Wi-Fi plus Ethernet, or Hyper-V/VPN adapters, would otherwise fool us).
function Pick-Nic {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric } |
        Select-Object -First 1
    if ($route) { return Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue }
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1
}

function Save-State($s) { $s | ConvertTo-Json | Set-Content -Path $State -Encoding utf8 }

function Refresh-Dns {
    Restart-Service Dnscache -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

if ($Mode -eq 'set') {
    $p = $Providers[$Provider]
    $nic = Pick-Nic
    if (-not $nic) { L 'no active network adapter'; exit 2 }

    # Keep the ORIGINAL servers if a previous set was never restored (provider
    # switch, app restart). Overwriting them would make Undo restore our own DNS.
    $prev = if (Test-Path $State) { Get-Content $State -Raw | ConvertFrom-Json } else { $null }
    # The saved state belongs to another adapter: overwriting it would lose that
    # adapter's original servers for good, so make the user undo first.
    if ($prev -and $prev.idx -ne $nic.ifIndex) { L "state belongs to $($prev.name), active is $($nic.Name)"; exit 4 }
    $original = if ($prev) { @($prev.dns) }
                else { @((Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex).ServerAddresses) }
    $dohAdded = if ($prev -and $prev.dohAdded) { @($prev.dohAdded) } else { @() }

    # Windows only knows DoH templates for a few providers; register the rest.
    # Add-DnsClientDohServerAddress exists on Windows 11 only; plain DNS still applies on 10.
    if (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        foreach ($ip in $p.v4 + $p.v6) {
            if (-not (Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue)) {
                try {
                    Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $p.doh -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop | Out-Null
                    $dohAdded += $ip
                } catch { L "DoH template for $ip failed: $($_.Exception.Message)" }
            }
        }
    }

    Save-State @{ idx = $nic.ifIndex; name = $nic.Name; guid = $nic.InterfaceGuid; dns = $original;
                  provider = $Provider; dohAdded = @($dohAdded | Select-Object -Unique) }

    # Set-DnsClientServerAddress has no -AddressFamily: v4 and v6 go in one list.
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses ($p.v4 + $p.v6)
    foreach ($pair in @(@('Doh', $p.v4), @('Doh6', $p.v6))) {
        $base = Join-Path (Doh-Base $nic.InterfaceGuid) $pair[0]
        foreach ($ip in $pair[1]) {
            $k = Join-Path $base $ip
            New-Item -Path $k -Force | Out-Null
            New-ItemProperty -Path $k -Name 'DohFlags' -Value 1 -PropertyType QWord -Force | Out-Null
        }
    }
    Refresh-Dns
    L "$($nic.Name): [$($original -join ', ')] -> $Provider with DoH"
    exit 0
}

if ($Mode -eq 'restore') {
    if (-not (Test-Path $State)) { L 'nothing to restore'; exit 3 }
    $s = Get-Content $State -Raw | ConvertFrom-Json
    if ($s.dns -and @($s.dns).Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceIndex $s.idx -ServerAddresses @($s.dns)
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $s.idx -ResetServerAddresses
    }
    foreach ($ip in @($s.dohAdded)) {
        if ($ip) { Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue }
    }
    foreach ($leaf in @('Doh', 'Doh6')) {
        $k = Join-Path (Doh-Base $s.guid) $leaf
        if (Test-Path $k) { Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Refresh-Dns
    Remove-Item $State -Force -ErrorAction SilentlyContinue
    L "$($s.name): DNS restored"
    exit 0
}
