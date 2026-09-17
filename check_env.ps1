<#
.SYNOPSIS
    Port Console 环境健康诊断与自愈检查脚本
#>
param(
    [switch]$Repair
)

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host " 🩺 Port-Console 环境体检与诊断工具" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查 Python 解释器
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[❌ 错误] 未检测到系统 Python。请先安装 Python 3.10+ 并勾选 Add to PATH。" -ForegroundColor Red
    exit 1
}
$pyVersion = & python --version 2>&1
Write-Host "[✓ 正常] Python 解释器: $($pythonCmd.Source) ($pyVersion)" -ForegroundColor Green

# 2. 检查 UV 极速安装器
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($uvCmd) {
    $uvVer = & uv --version 2>&1
    Write-Host "[✓ 正常] 检测到 UV 极速包管理器: $uvVer" -ForegroundColor Green
} else {
    Write-Host "[ℹ️ 提示] 未检测到 uv (建议运行 pip install uv 以获得秒级依赖补全)" -ForegroundColor Yellow
}

# 3. 检查控制台核心运行依赖 (psutil)
$hasPsutil = & python -c "import psutil; print('ok')" 2>$null
if ($hasPsutil -ne "ok") {
    Write-Host "[⚠️ 警告] 控制台核心依赖 psutil 缺失！" -ForegroundColor Yellow
    if ($Repair) {
        Write-Host "正在自动安装 psutil..." -ForegroundColor Cyan
        & python -m pip install psutil
    } else {
        Write-Host "建议运行: python -m pip install -r requirements.txt 或运行 .\check_env.ps1 -Repair" -ForegroundColor Yellow
    }
} else {
    Write-Host "[✓ 正常] 控制台核心依赖 (psutil) 已就绪" -ForegroundColor Green
}

# 4. 执行内部全局项目体检
Write-Host ""
Write-Host "正在体检所有已登记项目环境与端口状态..." -ForegroundColor Cyan
Write-Host ""

$output = & python -c "import sys; sys.path.insert(0, r'$ProjectRoot'); import server, json; rep = server.run_system_doctor(); print('__DOCTOR_JSON__'); print(json.dumps(rep, ensure_ascii=False))" 2>&1

$jsonLines = @()
$capture = $false
foreach ($line in $output) {
    if ($line -match "__DOCTOR_JSON__") {
        $capture = $true
        continue
    }
    if ($capture) {
        $jsonLines += $line
    }
}

if (-not $jsonLines) {
    Write-Host "[❌ 错误] 运行体检引擎失败: $output" -ForegroundColor Red
    exit 1
}

$rawJson = $jsonLines -join "`n"
$rep = $rawJson | ConvertFrom-Json
$sum = $rep.summary

Write-Host "【体检汇总】" -ForegroundColor White
Write-Host "  - 登记项目总数 : $($sum.total)"
Write-Host "  - 完全健康项目 : $($sum.healthy)" -ForegroundColor Green
if ($sum.missing_paths -gt 0) {
    Write-Host "  - 目录失效项目 : $($sum.missing_paths) (建议网页端点击【自动归档失效项】)" -ForegroundColor Red
} else {
    Write-Host "  - 目录失效项目 : 0" -ForegroundColor Green
}
if ($sum.drift_ports -gt 0) {
    Write-Host "  - 端口漂移生效 : $($sum.drift_ports) (动态端口已正常识别接管)" -ForegroundColor Yellow
}
if ($sum.port_conflicts -gt 0) {
    Write-Host "  - 潜在端口冲突 : $($sum.port_conflicts)" -ForegroundColor Red
}

Write-Host ""
Write-Host "【各项目明细】" -ForegroundColor White
foreach ($p in $rep.projects) {
    $statusText = if ($p.healthy) { "[✓ 健康]" } else { "[! 异常]" }
    $statusColor = if ($p.healthy) { "Green" } else { "Red" }
    $archivedTag = ""
    if (-not $p.enabled) {
        $archivedTag = " (已归档)"
    }
    Write-Host "$statusText $($p.name)$archivedTag" -ForegroundColor $statusColor
    foreach ($c in $p.checks) {
        $lvlColor = "Gray"
        if ($c.level -eq "error") { $lvlColor = "Red" }
        elseif ($c.level -eq "warn") { $lvlColor = "Yellow" }
        elseif ($c.level -eq "info") { $lvlColor = "Gray" }

        $mark = if ($c.ok) { "  - " } else { "  * " }
        Write-Host "$mark$($c.item): $($c.message)" -ForegroundColor $lvlColor
        if ($c.suggestion) {
            Write-Host "    -> 建议: $($c.suggestion)" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host " 💡 提示：在网页端点击【🩺 环境体检】或【🧹 自动归档失效项】可可视化一键处理。" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
