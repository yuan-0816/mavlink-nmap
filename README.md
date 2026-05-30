## Nmap 客製化掃描 mavlink udp 腳本引擎 (nse)
#### 適用 mission planner, qgroundcontrol 地面站軟體的 mavlink 協定分析與掃描。
--- 
### 需求
- Nmap

### 安裝方式 (windows)
#### 1. clone Repo
```
git clone https://github.com/yuan-0816/mavlink-nmap.git && cd mavlink-nmap
``` 

#### 2. 複製官方完整檔(注意:複製成沒有副檔名的 nmap-service-probes)
```
Copy-Item "C:\Program Files (x86)\Nmap\nmap-service-probes" .\nmap-service-probes
```
#### 3. 把自訂片段接到最後面
```
Get-Content .\nmap-service-probes-mavlink.txt | Add-Content .\nmap-service-probes
```

#### 4. 更新 nmap 的腳本資料庫
```
nmap --script-updatedb
```

### 使用方式
```
# TCP 全 port + 標準/弱點腳本
nmap -sS -sV -p- -T4 --script "default,vuln" <GCS IP>

# UDP 全 port + MAVLink 偵測
nmap -sU -sV -p- -T4 --datadir . --script "default,.\mavlink-detect.nse" <GCS IP>
```
#### 參數說明
```-sS```:TCP SYN 掃描
```-sU```:UDP 掃描
```-sV```:開啟版本偵測,當前目錄、自訂的 nmap-service-probes
```--datadir .```:維持讀取當前目錄 probes / services。
```--script "default,vuln,.\mavlink-detect.nse"```:同時跑 Nmap 內建的 default、vuln 類別腳本,外加 mavlink-detect.nse。