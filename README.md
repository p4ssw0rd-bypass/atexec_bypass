# Atexec.cpp 改进说明

## 概述

对 `atexec.cpp` 进行了改进，增加了随机化和隐蔽性特征，以降低被检测的风险。

---

## 主要改进

### 1. 随机化功能

#### 1.1 任务名称随机化
- **原来**: 固定使用 `TestBody`
- **现在**: 动态生成看起来像系统任务的名称
- **示例**: 
  - `BackgroundProcessor`
  - `SystemMonitor`
  - `NetworkHandler`
  - `DiagnosticService`

#### 1.2 任务路径随机化
- **原来**: 固定使用 `\Microsoft\Windows\AppID`
- **现在**: 从20+个合法系统路径中随机选择
- **路径列表**:
  - `\Microsoft\Windows\Application Experience`
  - `\Microsoft\Windows\Defrag`
  - `\Microsoft\Windows\Diagnosis`
  - `\Microsoft\Windows\Maintenance`
  - 等等...

#### 1.3 输出文件随机化
- **原来**: 固定使用 `C:\Windows\RunTime.log`
- **现在**: 从多个临时文件名中随机选择
- **示例**:
  - `C:\Windows\Temp\temp.log`
  - `C:\Windows\Temp\cache.tmp`
  - `C:\Windows\Temp\diagnostic.txt`
  - `C:\Windows\Temp\update.log`

#### 1.4 作者名称随机化
- **原来**: 固定使用 `Microsoft Corporation`
- **现在**: 从多个可信作者中随机选择
- **选项**:
  - `Microsoft Corporation`
  - `Microsoft Windows`
  - `Windows System`
  - `System Administrator`
  - `NT AUTHORITY\SYSTEM`

#### 1.5 时间参数随机化
- **执行延迟**: 从固定的10秒改为 1-3秒随机（快速执行）
- **结束时间**: 从固定的 `2089-03-26T13:00:00` 改为 1-3年后的随机日期

#### 1.6 触发器ID随机化
- **原来**: 固定使用 `Trigger2`
- **现在**: `Trigger` + 6位随机字符串
- **示例**: `TriggerA3x9Zp`

---

### 2. 伪装功能

#### 2.1 命令末尾添加伪装注释
在每个执行的命令末尾自动添加:
```batch
& REM NVDisplay.ContainerLocalSystem
```

这使得命令看起来像是 NVIDIA 显示容器服务执行的操作。

**示例效果**:
```batch
原命令: whoami
执行命令: cmd /c whoami >C:\Windows\Temp\temp.log & REM NVDisplay.ContainerLocalSystem
```

#### 2.2 改进的输出信息
- 使用专业的进度提示 `[*]`, `[+]`, `[-]`
- 更详细的操作日志
- 清晰的状态反馈

---

## 新增函数

### 随机化辅助函数

```cpp
// 生成随机字符串
std::wstring GenerateRandomString(int length)

// 随机选择任务路径
std::wstring GetRandomTaskPath()

// 生成随机任务名称
std::wstring GenerateRandomTaskName()

// 生成随机输出文件名
std::wstring GenerateRandomOutputFile()

// 随机选择作者名称
std::wstring GetRandomAuthor()

// 生成随机时间延迟（1-3秒）
int GetRandomDelay()
```

---

## 使用方式

### 编译

```bash
cl /EHsc atexec.cpp /link taskschd.lib comsupp.lib ws2_32.lib Mpr.lib Advapi32.lib
```

### 使用

```bash
# 基本用法（与之前相同）
atexec.exe <Host> <Username> <Password> <Command> [Domain]

# 示例
atexec.exe 192.168.1.100 administrator P@ssw0rd123 whoami
atexec.exe 192.168.1.100 administrator P@ssw0rd123 "net user" CONTOSO.COM
```

### 输出示例

```
============================================
  Advanced Task Execution Tool v2.0
  With Randomization & Stealth Features
============================================

[*] Initializing randomization...
[*] Generated task name: NetworkHandler
[*] Output file: C:\Windows\Temp\diagnostic.txt
[*] Author: Microsoft Windows
[*] Execution delay: 8 seconds

[*] Connecting to task scheduler on 192.168.1.100...
[+] Successfully connected!

[*] Creating scheduled task...
[*] Using task path: \Microsoft\Windows\Diagnosis
[*] Task will execute at: 2025-01-06T15:23:45
[+] Task created successfully!

[*] Waiting for task execution (8 seconds)...
[*] Cleaning up task...

[*] Retrieving command output via SMB...
[+] SMB connection established!

===========================
DOMAIN\Administrator
===========================

[+] Operation completed successfully!

============================================
```

---

## 隐蔽性提升

### 1. 任务特征混淆
- ✅ 任务名称看起来像系统任务
- ✅ 任务路径在合法的系统目录中
- ✅ 作者字段使用可信名称
- ✅ 文件名不引起怀疑

### 2. 时间特征随机化
- ✅ 执行延迟不固定
- ✅ 结束时间合理且随机
- ✅ 触发器ID每次不同

### 3. 命令伪装
- ✅ 添加NVIDIA服务注释
- ✅ 看起来像合法服务操作

### 4. 行为特征
- ✅ 使用临时目录
- ✅ 任务执行后自动清理
- ✅ 日志输出专业规范

---

## 参考&感谢
[https://payloads.online/archivers/2020-06-28/1/](https://github.com/Rvn0xsy/MyWin32CPP/blob/master/Atexec.cpp)
https://xz.aliyun.com/news/18192
