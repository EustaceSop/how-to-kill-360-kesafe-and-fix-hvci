# 為什麼 HVCI 打不開 —— 一場對 360 Kesafe 自癒核心驅動的獵殺

> Windows 10/11「核心隔離 / 記憶體完整性(HVCI）」怎麼開都開不起來的完整診斷與根除實錄。
> 硬體全合格,真正的攔阻是四支 **W+X 不相容核心驅動**,以及一支會不斷改名重生的 **360 Kesafe 核晶**反作弊守護。

**環境**：AMD Ryzen 7 9700X · Windows 10 22H2 (19045) · Secure Boot ON · TPM 2.0
**觸發**：Valorant Vanguard（VGC）要求開啟記憶體完整性
**結果**：✅ HVCI 執行中 · 360 Kesafe 已根除

---

## 目錄

- [TL;DR](#tldr)
- [根因：問題其實有兩層](#根因問題其實有兩層)
- [四支 HVCI 不相容驅動](#四支-hvci-不相容驅動)
- [主戰場：360 Kesafe 攻防](#主戰場360-kesafe-攻防)
- [決勝關鍵](#決勝關鍵)
- [可重現的完整流程](#可重現的完整流程)
- [驗證](#驗證)
- [附錄 A：偵測腳本](#附錄-a偵測腳本)
- [附錄 B：關鍵技術與環境陷阱](#附錄-b關鍵技術與環境陷阱)
- [免責聲明](#免責聲明)

---

## TL;DR

「HVCI 打不開」= 三件事疊加：

1. **VBS 平台沒被啟用**（`hypervisorlaunchtype` 缺席、DeviceGuard 登錄沒開）—— 易修。
2. **HVCI 被 4 支 W+X 核心驅動擋住** —— Windows 每次開機把 `HypervisorEnforcedCodeIntegrity\Enabled` 自動重設回 `0`。
3. **其中一支是 360 Kesafe，會改名重生** —— 直接刪它，它會在關機瞬間丟出改名的新種子復活。

決勝關鍵：對付自癒核心驅動要**先 `sc stop` 乾淨停止,再刪除服務與檔案**。

| 指標 | 值 | 意義 |
|---|---|---|
| `VirtualizationBasedSecurityStatus` | `2` | VBS 執行中 |
| `SecurityServicesRunning` | `{2}` | HVCI / 記憶體完整性 執行中 |
| `CI\State\HVCIEnabled` | `1` | Code Integrity 確認啟用 |
| Kesafe 殘留 | `0` | 檔案 / 服務皆無 |

---

## 根因：問題其實有兩層

### L1 — VBS 平台被整套關掉（早期已修復）

- BCD 沒有 `hypervisorlaunchtype`
- Hyper-V / VirtualMachinePlatform / HypervisorPlatform 選用功能全 `Disabled`
- `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` 底下**沒有** `EnableVirtualizationBasedSecurity`

> 硬體（SVM/AMD-V、SLAT/NPT、Secure Boot、TPM 2.0）全程合格,從不是瓶頸。VBS 不需要安裝 Hyper-V 功能 —— 它用的是 OS 內建的 `hvix64/hvax64`。

### L2 — HVCI 被 4 支 W+X 驅動擋住（主戰場）

VBS 起來（status 2）後,HVCI 仍每次開機被自動關掉。原因是存在 HVCI 不相容的核心驅動：只要有任何一支帶 **W+X（同時可寫可執行）section** 或非頁對齊,Windows 就拒絕 arm HVCI 並把 `Enabled` 重設回 `0`。

> ⚠️ `Microsoft-Windows-CodeIntegrity/Operational` 日誌預設可能是**停用**狀態，導致看不到 3082/3083 不相容驅動事件。先 `wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /e:true` 打開它。

---

## 四支 HVCI 不相容驅動

全掃 174 支載入驅動的 PE section 後揪出：

| 驅動 | 真實身分 | 特徵 | 處置 |
|---|---|---|---|
| `YwkFK.sys` → `FckFK` → `IwkFK` → `TlkFK` | **360 Kesafe 核晶**（`kemon.sys`, 360.cn, v1.0.0.1107） | W+X · Boot · 隨機改名 · 服務鍵自我隱藏 · **自癒** | ✅ `sc stop` → `delete` |
| `BAPIDRV64.sys` | 360 BYOVD 驅動（`360compkill` 強殺工具留下） | W+X · System · 雙服務註冊 | ✅ `sc delete` + 刪檔 |
| `tap0901.sys` | 舊版 OpenVPN **TAP-Windows V9** 虛擬網卡 | W+X · **未簽章** · PnP | ✅ `pnputil /delete-driver` |
| `WCHUSBNICA64.sys` | WCH 沁恒 USB 網卡（**kmbox net** 用） | W+X · PnP | ✅ 移除（kmbox net 犧牲） |

**保留不動**：火絨（`hrdevmon` / `sysdiag` / `hrwfpdrv`）是 HVCI 相容的。
**排除的誤導項**：`h2gPNXaS.sys`（改名的微軟 usbstor）、`CoreHost.sys` / `InputManagerjIomb`（輸入注入工具）。

---

## 主戰場：360 Kesafe 攻防

Kesafe 是 Boot 啟動、隨機命名（`??kFK.sys`）、服務鍵在執行期被內核 registry filter 隱藏（`reg query` 讀不到但 `sc query` / WMI 看得到）、且會**自我複製與改名重生**的核心驅動。所有複本 MD5 相同：`B73CE249F80A449DDF566191F49D570B`。

每清一次就換張臉回來：

```mermaid
flowchart LR
    A["YwkFK.sys"] -->|"刪除"| B["FckFK.sys"]
    B -->|"刪除"| C["IwkFK.sys"]
    C -->|"刪除"| D["TlkFK.sys"]
    D -->|"先 sc stop 再刪"| E(["✕ 死亡"])
    style E fill:#0c7a55,color:#fff
```

| 回合 | 動作 | Kesafe 回應 |
|---|---|---|
| R1 | 清掉靜態複本池（`FckFK`/`ilkFK`/`PpkFK` + `FsWriteBack64`），再刪載入中的 `FckFK` | ↻ 重生 → `IwkFK.sys`（關機瞬間丟種子） |
| R2 | `IwkFK` 是無服務、未載入的死種子；刪掉、設 `Enabled=1` | ↻ 重生 → `TlkFK.sys`（這次還帶 Boot 服務） |
| R3 | 頓悟：前幾次都趁驅動**常駐**時刪檔；改成先 `sc stop` 再刪，並武裝 4663 稽核陷阱 | 已移除,待驗證 |
| R4 | 正常開機 | ✅ 無任何 `*FK.sys` 重生 · HVCI arm 成功 |

---

## 決勝關鍵

> **對抗自癒核心驅動：先 `sc.exe stop` 乾淨停止,再刪除服務與檔案。**

前三回合失敗的唯一原因：直接趁驅動常駐（`STATE: RUNNING` / `STOP_PENDING` + `IGNORES_SHUTDOWN`）時刪檔,`IGNORES_SHUTDOWN` 的驅動會在關機瞬間丟出一份改名的新種子復活。乾淨停止後,記憶體裡不再有常駐驅動,就沒有東西能再造它 —— 鏈條就此斷裂。

---

## 可重現的完整流程

> 全部需**系統管理員**權限。這些是破壞性操作,請先確認每支驅動屬於什麼、你是否真的要移除（見[免責聲明](#免責聲明)）。

### 1. 啟用 VBS 平台

```powershell
bcdedit /set hypervisorlaunchtype Auto
$dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$hv = "$dg\Scenarios\HypervisorEnforcedCodeIntegrity"
Set-ItemProperty $dg -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord
Set-ItemProperty $dg -Name RequirePlatformSecurityFeatures  -Value 1 -Type DWord   # 1 = Secure Boot
Set-ItemProperty $hv -Name Enabled -Value 1 -Type DWord
wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /e:true                  # 打開日誌以便診斷
```

### 2. 找出所有 HVCI 不相容驅動

見 [附錄 A](#附錄-a偵測腳本) 的 `Test-HvciCompatible` 全掃腳本。

### 3. 移除不相容驅動

```powershell
# 一般（非 PnP）服務驅動 —— 自癒驅動務必先 stop
sc.exe stop   <ServiceName>
sc.exe delete <ServiceName>
[IO.File]::Delete("C:\Windows\System32\drivers\<name>.sys")   # 避開會被攔截的 del/Remove-Item

# PnP 驅動（TAP、USB 網卡等）—— 連驅動包一起移除,否則 PnP 會重建
pnputil /enum-drivers                                   # 找出對應的 oemNN.inf
pnputil /delete-driver oemNN.inf /uninstall /force
```

### 4. 重開機並驗證（見[驗證](#驗證)）

### 5.（可選）若仍被回滾：武裝稽核陷阱抓再生器

```powershell
auditpol.exe /set /subcategory:"File System" /success:enable
$acl  = Get-Acl 'C:\Windows\System32\drivers'
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','CreateFiles,WriteData','None','None','Success')
$acl.AddAuditRule($rule); Set-Acl 'C:\Windows\System32\drivers' $acl
# 重開後：查 Security 日誌 Event 4663，看是「誰」建立了新的 *.sys
```

---

## 驗證

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning

reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\State" /v HVCIEnabled
```

**成功條件**：`VirtualizationBasedSecurityStatus = 2` 且 `SecurityServicesRunning` 含 `2`，`HVCIEnabled = 1`。
或直接看：**Windows 安全性 → 裝置安全性 → 核心隔離 → 記憶體完整性 = 開啟**。

`SecurityServicesRunning` / `SecurityServicesConfigured` 代碼：`1` = Credential Guard，`2` = HVCI（記憶體完整性）。

---

## 附錄 A：偵測腳本

### A1. 批次 PE W^X 掃描（找出 HVCI 不相容的載入驅動）

```powershell
function Test-HvciCompatible($path) {
    try { $b = [IO.File]::ReadAllBytes($path) } catch { return $null }
    if ($b.Length -lt 0x100) { return $null }
    $e = [BitConverter]::ToInt32($b, 0x3C); $coff = $e + 4
    if ([BitConverter]::ToUInt32($b, $e) -ne 0x4550) { return $null }   # 'PE\0\0'
    $numSec = [BitConverter]::ToUInt16($b, $coff + 2)
    $optSz  = [BitConverter]::ToUInt16($b, $coff + 16)
    $opt    = $coff + 20
    $secAlign = [BitConverter]::ToUInt32($b, $opt + 32)
    $st = $opt + $optSz; $wx = 0
    for ($i = 0; $i -lt $numSec; $i++) {
        $ch = [BitConverter]::ToUInt32($b, ($st + $i*40) + 36)
        if ((($ch -band 0x80000000) -ne 0) -and (($ch -band 0x20000000) -ne 0)) { $wx++ }  # WRITE + EXECUTE
    }
    return (($wx -eq 0) -and ($secAlign -ge 0x1000))   # $false = HVCI 不相容
}

function Convert-DriverPath($p) {
    if (-not $p) { return $null }
    $p = $p -replace '^\\\?\?\\','' -replace '(?i)^\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '(?i)^system32\\') { $p = $env:SystemRoot + '\' + $p }
    return $p
}

Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | ForEach-Object {
    $f = Convert-DriverPath $_.PathName
    if ($f -and (Test-Path $f) -and ((Test-HvciCompatible $f) -eq $false)) {
        $sig = try { (Get-AuthenticodeSignature $f).SignerCertificate.Subject } catch { '?' }
        "[BLOCK] {0,-16} {1}  | {2}" -f $_.Name, $f, $sig
    }
}
```

### A2. Hash 偵測（對抗隨機改名 —— 名稱無關）

```powershell
$kesafe = 'B73CE249F80A449DDF566191F49D570B'   # 360 Kesafe kemon.sys
Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter *.sys -File | ForEach-Object {
    if ((Get-FileHash $_.FullName -Algorithm MD5).Hash -eq $kesafe) { "KESAFE: $($_.Name)" }
}
```

---

## 附錄 B：關鍵技術與環境陷阱

| 主題 | 重點 |
|---|---|
| **偵測** | 直接讀 PE section 的 `WRITE+EXECUTE` 旗標與 `SectionAlignment` —— 不靠簽章、不靠事件日誌 |
| **對抗改名** | 用內容 MD5 hash 掃描,任它改幾次名都現形 |
| **PnP 移除** | 只刪服務會被 PnP 重建;`pnputil /delete-driver … /uninstall /force` 連驅動包一起清 |
| **自癒驅動** | 先 `sc stop` 再 `sc delete` + 刪檔;未載入的備援可直接 `[IO.File]::Delete` |
| **鑑識** | `auditpol` + drivers 資料夾 SACL → Event 4663 抓「誰」建立檔案 |
| **PS 5.1 編碼** | 無 BOM 的中文 `.ps1` 會被 ANSI 碼頁解析成亂碼;須存為 **UTF-8 with BOM** |
| **服務鍵隱藏** | Kesafe 用內核 registry callback 隱藏服務鍵,`reg query` 讀不到,但 `sc query` / WMI `Win32_SystemDriver` 看得到 |

---

## 免責聲明

- 本文件記錄的是在**自有機器**上、為啟用 Microsoft 官方安全功能（HVCI）而清除**不需要的殘留驅動**的過程,屬系統維護 / 安全研究性質。
- 所有指令皆為**破壞性**且需系統管理員權限。執行前請確認每支驅動的來源與用途 —— 移除前務必了解你在移除什麼。
- 移除 **360 Kesafe / 安全卫士** 元件前,若你仍在使用 360 產品,請優先用其官方卸載工具。
- 移除 `WCHUSBNICA64` 會使依賴該 USB 網卡的裝置（如 kmbox net）停止運作。
- HVCI 啟用後會阻擋未通過的核心驅動(Cheat Engine DBVM、kernel debug、DBK64 等);需要時可再關閉。
- 自負風險。建議先建立系統還原點,並備妥 Windows RE(修復環境)以防開機異常。

---

<sub>Kernel Incident Post-Mortem · HVCI × 360 Kesafe · Ryzen 7 9700X / Windows 10 22H2 · 證據優先 · 零猜測</sub>
