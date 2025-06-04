# Florida Enhanced Frida 🛡️

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Version](https://img.shields.io/badge/version-16.7.19--enhanced-blue)](#)
[![Platform](https://img.shields.io/badge/platform-android-green)](#)
[![License](https://img.shields.io/badge/license-MIT-yellow)](#)

> **增强版Frida** - 专为Android平台优化的动态分析工具，集成深度反检测技术


### 本项目修改自https://github.com/Ylarod/Florida

## ✨ 特色功能

🛡️ **反检测能力** - 有效绕过常见的反调试和反Hook检测  
🎯 **高成功率** - 在各种Android应用中验证可用  
🚀 **开箱即用** - 预编译版本，下载即可使用  
🔧 **全架构支持** - ARM、ARM64、x86、x86_64 全覆盖  

## 🎯 主要改进

| 功能 | 状态 |
|------|------|
| **进程隐藏** | ✅
| **符号混淆** | ✅ 
| **内存伪装** | ✅ 
| **反检测脚本** | ✅ 
| **协议优化** | ✅ 

## 🚀 快速开始

### 1️⃣ 下载预编译版本

前往 [Releases页面](https://github.com/imkenf/Florida/releases/latest) 下载对应架构的文件：

```bash
# ARM64架构 (推荐)
wget https://github.com/imkenf/Florida/releases/download/16.7.19-enhanced-v2.0/florida-enhanced-server-16.7.19-android-arm64.gz

# 解压并设置权限
gunzip florida-enhanced-server-16.7.19-android-arm64.gz
chmod +x florida-enhanced-server-16.7.19-android-arm64
```

### 2️⃣ 部署到Android设备

```bash
# 推送到设备
adb push florida-enhanced-server-16.7.19-android-arm64 /data/local/tmp/frida-server

# 启动服务
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

### 3️⃣ 连接使用

```python
import frida

# 连接到增强版Frida
device = frida.get_usb_device()
session = device.attach("目标应用包名")

# 注入脚本
script = session.create_script("""
    Java.perform(function() {
        // 你的Hook代码
        console.log("Florida Enhanced Frida 已连接！");
    });
""")
script.load()
```

## 📱 支持的设备

### Android版本要求
- **最低版本**: Android 5.0 (API 21)
- **推荐版本**: Android 7.0+ (更好的兼容性)
- **Root权限**: 推荐但非必需

### 支持的架构
| 架构 | 兼容性 | 下载 |
|------|--------|------|
| **ARM64** | ✅ 主流设备 | [下载](https://github.com/imkenf/Florida/releases/latest) |
| **ARM** | ✅ 老旧设备 | [下载](https://github.com/imkenf/Florida/releases/latest) |
| **x86_64** | ✅ 模拟器 | [下载](https://github.com/imkenf/Florida/releases/latest) |
| **x86** | ✅ 老模拟器 | [下载](https://github.com/imkenf/Florida/releases/latest) |

## 🔍 与原版Frida对比

| 特性 | 原版Frida | Florida Enhanced |
|------|-----------|------------------|
| **基础功能** | ✅ | ✅ |
| **易被检测** | ❌ 容易 | ✅ 困难 |
| **进程名隐藏** | ❌ | ✅ |
| **符号混淆** | ❌ | ✅ |
| **反检测脚本** | ❌ | ✅ |
| **配置复杂度** | 简单 | 简单 |

## 📦 完整组件

下载的压缩包包含以下组件：

- **frida-server** - 主服务程序 (~23MB)
- **frida-inject** - 注入工具 (~23MB)  
- **frida-gadget** - 动态库组件 (~10MB)
- **frida-gumjs** - JavaScript引擎 (~4MB)

## ⚠️ 使用须知

### 合法使用
- 仅用于**安全研究**和**渗透测试**
- 仅在**自己拥有**或**获得授权**的设备上使用
- 不得用于**恶意攻击**或**非法目的**



## 🔗 相关项目

- [Frida](https://github.com/frida/frida) - 原版动态分析框架
- [Objection](https://github.com/sensepost/objection) - 移动应用安全测试工具
- [Xposed](https://github.com/rovo89/Xposed) - Android Hook框架


## ⭐ 如果有帮助

如果这个项目对您有帮助，请给我们一个⭐Star！这是对开发者最大的鼓励。

---

**🚨 免责声明**: 本工具仅供安全研究和教育用途，使用者需自行承担使用风险，开发者不对任何滥用行为负责。

**📱 Florida Enhanced - 让移动安全测试更简单！** 
