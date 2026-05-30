## Nmap 客製化掃描 mavlink udp 腳本引擎 (nse)
#### 適用 mission planner, qgroundcontrol 地面站軟體的 mavlink 協定分析與掃描。
--- 
### 需求
- Nmap

### 安裝方式 (windows)
#### 1. clone Repo
```
git clone && cd mavlink-nmap
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
nmap -sUV -p- --datadir . --script .\mavlink-detect.nse <GCS_IP>
```