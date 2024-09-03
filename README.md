### AutoNmap
```diff
@@ FOR ENTERTAINMENT PURPOSES ONLY, DEVELOPERS NOT RESPONSIBLE FOR USER ACTIONS @@
```

### Video
Usage on video deprececated: Please use the updated CLI. P.S.: Do not attempt to use credentials; they have been revoked.
[nmap_scan.webm](https://github.com/user-attachments/assets/b1cea1ea-1bee-4e39-8901-4adbfa73f8b2)



### Algorithm(lang: rus)
![plot](src/algorithm)

Usage: ./nmap.sh [OPTION]...

Purpose: Scan the network for open ports/services/operating systems/common CVEs. If HTTP{S} sites are located on any port, scan for directories/common CVEs.

**Run with sudo to grant permissions for SYN/Stealth scans.**

Syntax: `sudo ./nmap.sh -n 192.168.0.0/24 -i eth0 -c 3.0 -w 7kTi-sdfsdfa -a 7432893074:AAFHStvfsdjlkfsdsvTz3dsIDvET833RH8 -c 13279872 -l 172.16.0.2:9600`

  -h, --help            display this help and exit;
  -n, --network         specify host or network to scan; 
  -i, --interface       specify source network interface;
  -m, --mincvss         specify minimum CVSS score to display for vulscan nmap;
  -w, --wp-token        specify WPScan token for scanning sites based on WordPress;
  -a, --api-token-tg    specify token for Telegram API to send scan reports;
  -c, --chat-id-tg      specify Telegram chat ID to send scan reports;
  -l, --logstash-url    specify the Logstash host to which the logs should be sent.
