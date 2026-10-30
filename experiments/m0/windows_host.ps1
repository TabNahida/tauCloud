$ErrorActionPreference = 'Stop'
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$probe = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetworkV6, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
$bind445 = 'available'
try {
    $probe.DualMode = $true
    $probe.ExclusiveAddressUse = $true
    $probe.Bind([Net.IPEndPoint]::new([Net.IPAddress]::IPv6Any, 445))
} catch [Net.Sockets.SocketException] {
    $bind445 = $_.Exception.SocketErrorCode.ToString()
} finally { $probe.Dispose() }
$alternate = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try { $alternate.Start(); $alternateAvailable = $true } finally { $alternate.Stop() }
$drive = [IO.Path]::GetPathRoot([IO.Path]::GetTempPath()).TrimEnd('\')
$filesystem = (Get-Volume -DriveLetter $drive.Substring(0, 1)).FileSystem
[ordered]@{
    probe = 'windows_host'; status = 'passed'; version = $os.DisplayVersion
    build = ($os.CurrentBuild + '.' + $os.UBR); fixture_filesystem = $filesystem
    exclusive_bind_445 = $bind445; loopback_alternative_listener = $alternateAvailable
    services_modified = $false; remote_firewall_connectivity = 'not_tested'
} | ConvertTo-Json -Compress
