#!/usr/bin/env python3
"""
Florida Enhanced Anti-Detection Script
专为Frida 16.7.19设计的全面混淆和反检测工具
"""

import lief
import sys
import random
import os
import json
import hashlib
import struct
import logging
import time
from pathlib import Path
from typing import Dict, List, Callable, Optional, Tuple, Any

class EnhancedObfuscator:
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化增强型混淆器
        
        Args:
            config_path: 配置文件路径，默认在脚本同目录查找
        """
        self.logger = self._setup_logger()
        self.config = self._load_config(config_path)
        self.charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
        self.version = "2.0.0"
        self.logger.info(f"Florida Enhanced Anti-Detection v{self.version} 初始化")
        
    def _setup_logger(self) -> logging.Logger:
        """设置日志系统"""
        logger = logging.getLogger("florida-enhanced")
        logger.setLevel(logging.DEBUG)
        
        # 控制台处理器
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        
        # 设置格式
        formatter = logging.Formatter(
            "\033[1;36m[Florida]\033[0m %(levelname)s - %(message)s"
        )
        console.setFormatter(formatter)
        logger.addHandler(console)
        
        return logger
        
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        加载配置文件，如果指定路径不存在则使用默认路径
        
        Args:
            config_path: 可选的配置文件路径
            
        Returns:
            加载的配置对象
        """
        # 默认配置
        default_config = {
            "version": "2.0.0",
            "symbols": {"enable_obfuscation": True},
            "strings": {"enable_obfuscation": True},
            "thread_names": {"enable_obfuscation": True},
            "memory_layout": {"enable_obfuscation": True},
            "anti_debugging": {"enable": True},
            "logging": {"enable_verbose_logging": True}
        }
        
        # 尝试查找配置文件
        if not config_path:
            possible_paths = [
                Path(__file__).parent / "obfuscation_config.json",
                Path("/data/local/tmp/obfuscation_config.json"),
                Path("/tmp/obfuscation_config.json")
            ]
            
            for path in possible_paths:
                if path.exists():
                    config_path = str(path)
                    break
        
        # 加载配置文件
        if config_path and Path(config_path).exists():
            try:
                self.logger.info(f"从 {config_path} 加载配置")
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # 递归合并配置
                    return self._merge_configs(default_config, loaded_config)
            except Exception as e:
                self.logger.error(f"加载配置失败: {e}")
                return default_config
        
        self.logger.warning("未找到配置文件，使用默认配置")
        return default_config
    
    def _merge_configs(self, default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        递归合并配置对象
        
        Args:
            default: 默认配置
            override: 要覆盖的配置
            
        Returns:
            合并后的配置
        """
        result = default.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def log_color(self, msg: str, color: int = 36) -> None:
        """
        输出彩色日志
        
        Args:
            msg: 日志消息
            color: ANSI颜色代码
        """
        log_config = self.config.get("logging", {})
        if log_config.get("enable_verbose_logging", True):
            level = log_config.get("log_level", "info").lower()
            
            if level == "debug":
                self.logger.debug(f"\033[1;{color}m{msg}\033[0m")
            else:
                self.logger.info(f"\033[1;{color}m{msg}\033[0m")
    
    def generate_realistic_name(
        self, 
        length: int = 8, 
        prefix: str = "", 
        suffix: str = ""
    ) -> str:
        """
        生成逼真的名称
        
        Args:
            length: 名称总长度
            prefix: 前缀
            suffix: 后缀
            
        Returns:
            生成的名称
        """
        naming_config = self.config.get("symbols", {}).get("naming_strategy", {})
        system_prefixes = naming_config.get(
            "prefixes", 
            ["sys", "lib", "net", "io", "mem", "proc", "kern", "dev"]
        )
        system_suffixes = naming_config.get(
            "suffixes", 
            ["util", "core", "base", "mgr", "svc", "mod", "drv"]
        )
        
        if not prefix:
            prefix = random.choice(system_prefixes)
        if not suffix:
            suffix = random.choice(system_suffixes)
            
        middle_len = max(1, length - len(prefix) - len(suffix))
        middle = "".join(random.choices(self.charset[:52], k=middle_len))  # 只使用字母
        
        return f"{prefix}{middle}{suffix}"
    
    def _generate_seed_from_binary(self, binary_path: str) -> int:
        """
        从二进制文件生成稳定种子
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            整数种子
        """
        try:
            # 使用文件大小和修改时间作为种子基础
            file_stat = os.stat(binary_path)
            size = file_stat.st_size
            mtime = int(file_stat.st_mtime)
            
            # 加上当前时间的低位来增加随机性但保持一定稳定性
            current_time = int(time.time()) & 0xFFFF
            
            # 混合生成种子
            seed = (size ^ mtime) + current_time
            return seed & 0xFFFFFFFF
        except Exception as e:
            self.logger.warning(f"生成种子失败: {e}, 使用随机种子")
            return random.randint(1, 0xFFFFFFFF)
    
    def _verify_binary_integrity(self, binary: Any) -> bool:
        """
        验证二进制完整性
        
        Args:
            binary: LIEF二进制对象
            
        Returns:
            是否完整
        """
        try:
            # 简单测试部分API是否能正常工作
            _ = binary.header
            _ = binary.sections
            if hasattr(binary, "segments"):
                _ = binary.segments
            return True
        except Exception as e:
            self.logger.error(f"二进制完整性验证失败: {e}")
            return False
    
    def _replace_string_safely(
        self, 
        data: bytes, 
        pos: int, 
        original: str, 
        replacement: str
    ) -> bytes:
        """
        安全地替换二进制中的字符串
        
        Args:
            data: 原始数据
            pos: 起始位置
            original: 原始字符串
            replacement: 替换字符串
            
        Returns:
            修改后的数据
        """
        original_bytes = original.encode('utf-8')
        replacement_bytes = replacement.encode('utf-8')
        
        # 确保长度匹配
        if len(replacement_bytes) < len(original_bytes):
            padding = b'\x00' * (len(original_bytes) - len(replacement_bytes))
            replacement_bytes += padding
        elif len(replacement_bytes) > len(original_bytes):
            replacement_bytes = replacement_bytes[:len(original_bytes)]
            
        # 修改数据
        modified_data = bytearray(data)
        modified_data[pos:pos+len(original_bytes)] = replacement_bytes
        
        return bytes(modified_data)
    
    def obfuscate_symbols(self, binary: Any) -> None:
        """
        符号名称混淆
        
        Args:
            binary: LIEF二进制对象
        """
        symbol_config = self.config.get("symbols", {})
        if not symbol_config.get("enable_obfuscation", True):
            self.logger.info("符号混淆已禁用")
            return
            
        self.log_color("开始符号混淆...", 33)
        
        # 关键符号替换映射
        critical_symbols = symbol_config.get("critical_symbols", {
            "frida_agent_main": "main",
            "gum_": "sys_",
            "frida": "florida",
            "FRIDA": "FLORIDA"
        })
        
        # 模式替换
        pattern_replacements = symbol_config.get("pattern_replacements", {
            "frida_": "fl_",
            "gum_": "sys_",
            "_frida_": "_fl_"
        })
        
        # 跟踪替换统计
        symbol_count = 0
        
        # 获取所有符号
        if not hasattr(binary, "symbols"):
            self.logger.warning("二进制文件没有符号表")
            return
            
        for symbol in binary.symbols:
            if not hasattr(symbol, "name") or not symbol.name:
                continue
                
            original_name = symbol.name
            modified = False
            
            # 处理关键符号
            for pattern, replacement in critical_symbols.items():
                if pattern in symbol.name:
                    if pattern == "frida_agent_main" and symbol.name == pattern:
                        symbol.name = replacement
                    else:
                        symbol.name = symbol.name.replace(pattern, replacement)
                    modified = True
                    symbol_count += 1
                    break
            
            # 处理模式替换
            if not modified:
                for pattern, replacement in pattern_replacements.items():
                    if pattern in symbol.name:
                        symbol.name = symbol.name.replace(pattern, replacement)
                        modified = True
                        symbol_count += 1
                        break
            
            if modified:
                self.log_color(f"符号: {original_name} -> {symbol.name}", 33)
        
        self.log_color(f"符号混淆完成: 修改了 {symbol_count} 个符号", 32)
    
    def obfuscate_strings(self, binary: Any) -> None:
        """
        字符串混淆
        
        Args:
            binary: LIEF二进制对象
        """
        string_config = self.config.get("strings", {})
        if not string_config.get("enable_obfuscation", True):
            self.logger.info("字符串混淆已禁用")
            return
            
        self.log_color("开始字符串混淆...", 33)
        
        # 目标字符串及其替换策略
        target_strings = string_config.get("target_strings", [
            "FridaScriptEngine",
            "GLib-GIO",
            "GDBusProxy",
            "GumScript",
            "frida-gum",
            "frida-core",
            "/frida/",
            "frida:",
            "FRIDA_"
        ])
        
        # 是否使用字符串反转
        use_reverse = string_config.get("reverse_strings", True)
        
        # 跟踪替换统计
        string_count = 0
        
        # 处理所有可能包含字符串的节
        for section in binary.sections:
            # 只处理可能包含字符串的节
            if section.name not in [".rodata", ".data", ".dynstr"]:
                continue
                
            section_data = bytes(section.content)
            modified_data = bytearray(section_data)
            modified = False
            
            for target_str in target_strings:
                target_bytes = target_str.encode('utf-8')
                
                # 生成替换字符串
                if use_reverse and len(target_str) > 3:
                    # 使用反转策略
                    replacement_str = target_str[::-1]
                else:
                    # 使用随机生成策略
                    replacement_str = self.generate_realistic_name(len(target_str))
                
                # 替换所有出现
                start = 0
                while True:
                    pos = section_data.find(target_bytes, start)
                    if pos == -1:
                        break
                    
                    # 安全替换
                    replacement_bytes = replacement_str.encode('utf-8')
                    replacement_bytes = replacement_bytes[:len(target_bytes)]
                    if len(replacement_bytes) < len(target_bytes):
                        replacement_bytes += b'\x00' * (len(target_bytes) - len(replacement_bytes))
                    
                    modified_data[pos:pos+len(target_bytes)] = replacement_bytes
                    modified = True
                    string_count += 1
                    self.log_color(f"字符串: {target_str} -> {replacement_str} @{hex(pos)}", 33)
                    
                    start = pos + len(target_bytes)
            
            # 应用修改
            if modified:
                section.content = list(modified_data)
        
        self.log_color(f"字符串混淆完成: 修改了 {string_count} 个字符串", 32)
    
    def obfuscate_thread_names(self, binary_path: str) -> None:
        """
        线程名称混淆
        
        Args:
            binary_path: 二进制文件路径
        """
        thread_config = self.config.get("thread_names", {})
        if not thread_config.get("enable_obfuscation", True):
            self.logger.info("线程名称混淆已禁用")
            return
            
        self.log_color("开始线程名称混淆...", 33)
        
        # 使用预定义映射或生成新映射
        thread_mappings = thread_config.get("thread_mappings", {})
        
        if not thread_mappings:
            # 使用命名策略动态生成
            naming = thread_config.get("naming_strategy", {})
            prefixes = naming.get("prefixes", ["sys", "bg", "proc", "svc"])
            suffixes = naming.get("suffixes", ["loop", "main", "thrd", "wrk"])
            
            thread_mappings = {
                "gum-js-loop": f"{random.choice(prefixes)}-{random.choice(suffixes)}",
                "gmain": f"{random.choice(prefixes)}-main",
                "gdbus": f"{random.choice(prefixes)}-bus",
                "frida-helper": f"{random.choice(prefixes)}-helper",
                "agent-thread": f"{random.choice(prefixes)}-worker"
            }
        
        # 替换计数
        replaced = 0
        
        # 使用二进制编辑工具替换字符串
        for original, replacement in thread_mappings.items():
            # 确保替换字符串长度不超过原字符串
            safe_replacement = replacement[:len(original)]
            if len(safe_replacement) < len(original):
                safe_replacement += '\0' * (len(original) - len(safe_replacement))
            
            # 使用sed替换（安全方式）
            cmd = f"sed -b -i 's/{original}/{safe_replacement}/g' {binary_path} 2>/dev/null"
            result = os.system(cmd)
            
            if result == 0:
                self.log_color(f"线程名称: {original} -> {safe_replacement}", 33)
                replaced += 1
            else:
                self.logger.warning(f"替换失败: {original}")
        
        self.log_color(f"线程名称混淆完成: 修改了 {replaced} 个线程名称", 32)
    
    def obfuscate_memory_layout(self, binary: Any) -> None:
        """
        内存布局混淆
        
        Args:
            binary: LIEF二进制对象
        """
        memory_config = self.config.get("memory_layout", {})
        if not memory_config.get("enable_obfuscation", True):
            self.logger.info("内存布局混淆已禁用")
            return
            
        self.log_color("开始内存布局混淆...", 33)
        
        # 检查是否支持添加段
        if not hasattr(binary, "add") or not callable(binary.add):
            self.logger.warning("二进制格式不支持添加段，跳过内存布局混淆")
            return
        
        # 安全模式
        safe_mode = memory_config.get("safe_mode", True)
        
        # 段名称和大小配置
        section_names = memory_config.get("section_names", [".note.android", ".init_proc", ".sys_data"])
        min_size = memory_config.get("min_section_size", 64)
        max_size = memory_config.get("max_section_size", 256)
        max_sections = memory_config.get("max_sections", 2)
        
        # 添加假段
        added_sections = 0
        
        try:
            # 限制最大段数
            for name in section_names[:max_sections]:
                # 生成随机大小
                section_size = random.randint(min_size, max_size)
                # 生成随机内容
                dummy_content = [random.randint(0, 255) for _ in range(section_size)]
                
                try:
                    # 在安全模式下验证二进制完整性
                    if safe_mode and not self._verify_binary_integrity(binary):
                        self.logger.error("二进制完整性检查失败，跳过添加段")
                        break
                        
                    # 创建并添加段
                    dummy_section = lief.ELF.Section(name)
                    dummy_section.content = dummy_content
                    dummy_section.type = lief.ELF.SECTION_TYPES.PROGBITS
                    binary.add(dummy_section)
                    
                    added_sections += 1
                    self.log_color(f"添加混淆段: {name} (大小: {section_size}字节)", 33)
                    
                    # 再次验证完整性
                    if safe_mode and not self._verify_binary_integrity(binary):
                        self.logger.error("添加段后二进制损坏，跳过进一步修改")
                        break
                except Exception as e:
                    self.logger.error(f"添加段 {name} 失败: {e}")
                    if safe_mode:
                        break
            
            self.log_color(f"内存布局混淆完成: 添加了 {added_sections} 个混淆段", 32)
        except Exception as e:
            self.logger.error(f"内存布局混淆失败: {e}")
    
    def add_anti_debugging(self, binary: Any) -> None:
        """
        添加反调试技术
        
        Args:
            binary: LIEF二进制对象
        """
        debug_config = self.config.get("anti_debugging", {})
        if not debug_config.get("enable", True):
            self.logger.info("反调试功能已禁用")
            return
            
        self.log_color("添加反调试技术...", 33)
        
        # 字符串替换
        debug_strings = debug_config.get("string_replacements", {
            "ptrace": "sys_call",
            "debug": "verify",
            "trace": "check",
            "gdb": "idc"
        })
        
        replaced = 0
        
        # 处理相关节
        for section in binary.sections:
            if section.name in [".rodata", ".data"]:
                section_data = bytes(section.content)
                modified_data = bytearray(section_data)
                modified = False
                
                for debug_str, replacement in debug_strings.items():
                    debug_bytes = debug_str.encode('utf-8')
                    
                    # 查找并替换
                    start = 0
                    while True:
                        pos = section_data.find(debug_bytes, start)
                        if pos == -1:
                            break
                        
                        # 确保替换字符串长度匹配
                        replacement_bytes = replacement.encode('utf-8')
                        if len(replacement_bytes) < len(debug_bytes):
                            replacement_bytes += b'\x00' * (len(debug_bytes) - len(replacement_bytes))
                        elif len(replacement_bytes) > len(debug_bytes):
                            replacement_bytes = replacement_bytes[:len(debug_bytes)]
                        
                        # 替换字符串
                        modified_data[pos:pos+len(debug_bytes)] = replacement_bytes
                        modified = True
                        replaced += 1
                        self.log_color(f"反调试: {debug_str} -> {replacement}", 33)
                        
                        start = pos + len(debug_bytes)
                
                # 应用修改
                if modified:
                    section.content = list(modified_data)
        
        self.log_color(f"反调试功能添加完成: 修改了 {replaced} 处相关字符串", 32)
    
    def process_binary(self, input_file: str) -> bool:
        """
        处理二进制文件，应用所有混淆和反检测技术
        
        Args:
            input_file: 输入二进制文件路径
            
        Returns:
            处理是否成功
        """
        self.log_color(f"处理文件: {input_file}", 36)
        
        if not os.path.exists(input_file):
            self.logger.error(f"文件不存在: {input_file}")
            return False
        
        # 确保有写入权限
        if not os.access(input_file, os.W_OK):
            self.logger.error(f"无写入权限: {input_file}")
            return False
        
        # 创建备份
        backup_file = f"{input_file}.bak"
        try:
            import shutil
            shutil.copy2(input_file, backup_file)
            self.log_color(f"创建备份: {backup_file}", 36)
        except Exception as e:
            self.logger.warning(f"创建备份失败: {e}")
        
        try:
            # 解析二进制
            binary = lief.parse(input_file)
            if not binary:
                self.logger.error("解析二进制失败")
                return False
            
            # 应用混淆技术
            self.obfuscate_symbols(binary)
            self.obfuscate_strings(binary)
            self.obfuscate_memory_layout(binary)
            self.add_anti_debugging(binary)
            
            # 写回二进制
            self.log_color("写入修改后的二进制...", 36)
            binary.write(input_file)
            
            # 应用线程名称混淆（需要在写入二进制后）
            self.obfuscate_thread_names(input_file)
            
            self.log_color(f"处理完成: {input_file}", 32)
            return True
        except Exception as e:
            self.logger.error(f"处理二进制时发生错误: {e}")
            
            # 尝试恢复备份
            if os.path.exists(backup_file):
                try:
                    import shutil
                    shutil.copy2(backup_file, input_file)
                    self.log_color(f"已恢复备份: {input_file}", 33)
                except Exception as restore_e:
                    self.logger.error(f"恢复备份失败: {restore_e}")
            
            return False

def main():
    """主函数"""
    # 显示帮助信息
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        print("Florida Enhanced Anti-Detection Tool")
        print("用法: python3 enhanced-anti-detection.py <二进制文件> [配置文件]")
        print("例如: python3 enhanced-anti-detection.py /data/local/tmp/frida-server")
        sys.exit(1)
    
    # 获取参数
    binary_file = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # 创建混淆器并处理二进制
    obfuscator = EnhancedObfuscator(config_file)
    success = obfuscator.process_binary(binary_file)
    
    # 返回结果
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 