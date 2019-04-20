$ip = Read-Host "Enter IP in x.x.x.x: "

echo "Blocking OUTBOUND FOR $ip"
New-NetFirewallRule -DisplayName "Block $ip" -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress $ip
New-NetFirewallRule -DisplayName "Block $ip" -Direction Outbound -LocalPort Any -Protocol UDP -Action Block -RemoteAddress $ip
