#!/usr/bin/env python3
"""
Enhanced Anti-Detection Script for Frida
Provides comprehensive obfuscation and evasion techniques
"""

import lief
import sys
import random
import os
import hashlib
import struct
import json
from pathlib import Path

class EnhancedObfuscator:
    def __init__(self):
        self.config = self.load_config()
        self.charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
        self.log_enabled = True
        
    def load_config(self):
        """Load configuration from config file if exists"""
        config_path = Path(__file__).parent / "obfuscation_config.json"
        default_config = {
            "enable_symbol_obfuscation": True,
            "enable_string_obfuscation": True, 
            "enable_thread_name_obfuscation": True,
            "enable_memory_layout_obfuscation": True,
            "randomization_strength": "high",
            "preserve_functionality": True
        }
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
            except:
                return default_config
        return default_config
    
    def log_color(self, msg, color=31):
        """Enhanced logging with colors and verbosity control"""
        if self.log_enabled:
            print(f"\033[1;{color};40m{msg}\033[0m")
    
    def generate_realistic_name(self, length=8, prefix="", suffix=""):
        """Generate realistic looking names"""
        if self.config.get("randomization_strength") == "high":
            # Use system-like naming patterns
            system_prefixes = ["sys", "lib", "net", "io", "mem", "proc", "kern", "dev"]
            system_suffixes = ["util", "core", "base", "mgr", "svc", "mod", "drv"]
            
            if not prefix:
                prefix = random.choice(system_prefixes)
            if not suffix:
                suffix = random.choice(system_suffixes)
                
            middle_len = max(1, length - len(prefix) - len(suffix))
            middle = "".join(random.choices(self.charset[:52], k=middle_len))  # Only letters
            return f"{prefix}{middle}{suffix}"
        else:
            return "".join(random.choices(self.charset, k=length))
    
    def xor_encrypt_string(self, data, key):
        """XOR encrypt string data"""
        return bytes(b ^ key for b in data)
    
    def obfuscate_symbols(self, binary):
        """Enhanced symbol obfuscation"""
        if not self.config.get("enable_symbol_obfuscation"):
            return
            
        self.log_color("[*] Enhanced symbol obfuscation starting...")
        
        # Critical symbols to rename
        critical_symbols = {
            "frida_agent_main": "main",
            "gum_": self.generate_realistic_name(4, "sys", ""),
            "frida": self.generate_realistic_name(5),
            "FRIDA": self.generate_realistic_name(5).upper()
        }
        
        symbol_count = 0
        for symbol in binary.symbols:
            original_name = symbol.name
            modified = False
            
            # Handle critical symbols
            for pattern, replacement in critical_symbols.items():
                if pattern in symbol.name:
                    if pattern == "frida_agent_main":
                        symbol.name = replacement
                    else:
                        symbol.name = symbol.name.replace(pattern, replacement)
                    modified = True
                    symbol_count += 1
                    break
            
            if modified:
                self.log_color(f"[*] Symbol: {original_name} -> {symbol.name}", 33)
        
        self.log_color(f"[*] Obfuscated {symbol_count} symbols", 32)
    
    def obfuscate_strings(self, binary):
        """Enhanced string obfuscation in binary sections"""
        if not self.config.get("enable_string_obfuscation"):
            return
            
        self.log_color("[*] Enhanced string obfuscation starting...")
        
        # Strings to obfuscate with their replacement strategies
        target_strings = {
            "FridaScriptEngine": lambda x: x[::-1],  # Reverse
            "GLib-GIO": lambda x: self.generate_realistic_name(len(x)),
            "GDBusProxy": lambda x: self.generate_realistic_name(len(x)),
            "GumScript": lambda x: self.generate_realistic_name(len(x)),
            "frida-gum": lambda x: self.generate_realistic_name(len(x)),
            "frida-core": lambda x: self.generate_realistic_name(len(x)),
            "/frida/": lambda x: f"/{self.generate_realistic_name(5)}/",
            "frida:": lambda x: f"{self.generate_realistic_name(5)}:",
            "FRIDA_": lambda x: f"{self.generate_realistic_name(5)}_"
        }
        
        string_count = 0
        for section in binary.sections:
            if section.name not in [".rodata", ".data", ".dynstr"]:
                continue
                
            section_data = bytes(section.content)
            modified_data = bytearray(section_data)
            
            for target_str, replacement_func in target_strings.items():
                target_bytes = target_str.encode('utf-8')
                replacement_str = replacement_func(target_str)
                replacement_bytes = replacement_str.encode('utf-8')[:len(target_bytes)]
                replacement_bytes += b'\x00' * (len(target_bytes) - len(replacement_bytes))
                
                # Find and replace all occurrences
                start = 0
                while True:
                    pos = section_data.find(target_bytes, start)
                    if pos == -1:
                        break
                    
                    self.log_color(f"[*] String in {section.name}@{hex(pos)}: {target_str} -> {replacement_str}", 33)
                    modified_data[pos:pos+len(target_bytes)] = replacement_bytes
                    string_count += 1
                    start = pos + len(target_bytes)
            
            # Apply modifications
            section.content = list(modified_data)
        
        self.log_color(f"[*] Obfuscated {string_count} strings", 32)
    
    def obfuscate_thread_names(self, binary_path):
        """Enhanced thread name obfuscation using sed with better patterns"""
        if not self.config.get("enable_thread_name_obfuscation"):
            return
            
        self.log_color("[*] Enhanced thread name obfuscation starting...")
        
        thread_mappings = {
            "gum-js-loop": self.generate_realistic_name(11, "sys", "loop"),
            "gmain": self.generate_realistic_name(5, "", "main"),
            "gdbus": self.generate_realistic_name(5, "", "bus"),
            "frida-helper": self.generate_realistic_name(12, "sys", "hlpr"),
            "agent-thread": self.generate_realistic_name(12, "bg", "thrd")
        }
        
        for original, replacement in thread_mappings.items():
            cmd = f"sed -b -i 's/{original}/{replacement}/g' {binary_path}"
            result = os.system(cmd)
            if result == 0:
                self.log_color(f"[*] Thread: {original} -> {replacement}", 33)
            else:
                self.log_color(f"[!] Failed to replace {original}", 91)
    
    def obfuscate_memory_layout(self, binary):
        """Enhanced memory layout obfuscation"""
        if not self.config.get("enable_memory_layout_obfuscation"):
            return
            
        self.log_color("[*] Enhanced memory layout obfuscation starting...")
        
        # Add padding sections to confuse memory scanners
        try:
            # Create dummy sections with realistic names
            dummy_names = [".note.android", ".init_proc", ".sys_data"]
            for name in dummy_names[:1]:  # Limit to prevent binary corruption
                dummy_content = [random.randint(0, 255) for _ in range(random.randint(64, 256))]
                try:
                    dummy_section = lief.ELF.Section(name)
                    dummy_section.content = dummy_content
                    dummy_section.type = lief.ELF.SECTION_TYPES.PROGBITS
                    binary.add(dummy_section)
                    self.log_color(f"[*] Added dummy section: {name}", 33)
                except Exception as e:
                    self.log_color(f"[!] Failed to add section {name}: {e}", 91)
        except Exception as e:
            self.log_color(f"[!] Memory layout obfuscation failed: {e}", 91)
    
    def add_anti_debugging(self, binary):
        """Add anti-debugging techniques"""
        self.log_color("[*] Adding anti-debugging techniques...")
        
        # This would normally inject anti-debugging code
        # For now, just modify some debug-related strings
        debug_strings = ["ptrace", "debug", "trace", "gdb"]
        for section in binary.sections:
            if section.name in [".rodata", ".data"]:
                section_data = bytes(section.content)
                modified_data = bytearray(section_data)
                
                for debug_str in debug_strings:
                    debug_bytes = debug_str.encode('utf-8')
                    replacement = self.generate_realistic_name(len(debug_str))
                    replacement_bytes = replacement.encode('utf-8')
                    
                    pos = section_data.find(debug_bytes)
                    if pos != -1:
                        modified_data[pos:pos+len(debug_bytes)] = replacement_bytes
                        self.log_color(f"[*] Anti-debug: {debug_str} -> {replacement}", 33)
                
                section.content = list(modified_data)
    
    def process_binary(self, input_file):
        """Main processing function"""
        self.log_color(f"[*] Processing {input_file}", 36)
        
        if not os.path.exists(input_file):
            self.log_color(f"[!] File not found: {input_file}", 91)
            return False
        
        try:
            binary = lief.parse(input_file)
            if not binary:
                self.log_color("[!] Failed to parse binary", 91)
                return False
            
            # Apply obfuscation techniques
            self.obfuscate_symbols(binary)
            self.obfuscate_strings(binary)
            self.obfuscate_memory_layout(binary)
            self.add_anti_debugging(binary)
            
            # Write modified binary
            binary.write(input_file)
            
            # Apply thread name obfuscation
            self.obfuscate_thread_names(input_file)
            
            self.log_color(f"[+] Successfully processed {input_file}", 32)
            return True
            
        except Exception as e:
            self.log_color(f"[!] Error processing {input_file}: {e}", 91)
            return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 enhanced-anti-detection.py <binary_file>")
        sys.exit(1)
    
    obfuscator = EnhancedObfuscator()
    success = obfuscator.process_binary(sys.argv[1])
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 