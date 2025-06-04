#!/bin/bash
# Enhanced Florida Patches Auto-Apply Script
# Author: Enhanced Florida Team

set -e

# Colors for output
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Configuration
FRIDA_ROOT=$(pwd)
FRIDA_GUM_DIR="$FRIDA_ROOT/subprojects/frida-gum"
FRIDA_CORE_DIR="$FRIDA_ROOT/subprojects/frida-core"
ENHANCED_PATCHES_DIR="$FRIDA_ROOT/Florida-16.7.19/patches/improved"
BACKUP_DIR="$FRIDA_ROOT/backup_$(date +%Y%m%d_%H%M%S)"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "检查依赖项..."
    
    # Check if we're in the right directory
    if [[ ! -d "subprojects/frida-gum" ]] || [[ ! -d "subprojects/frida-core" ]]; then
        log_error "请在 frida 根目录下运行此脚本"
        exit 1
    fi
    
    # Check if enhanced patches exist
    if [[ ! -d "$ENHANCED_PATCHES_DIR" ]]; then
        log_error "找不到增强补丁目录: $ENHANCED_PATCHES_DIR"
        exit 1
    fi
    
    # Check required tools
    for tool in git patch python3; do
        if ! command -v $tool &> /dev/null; then
            log_error "缺少必需工具: $tool"
            exit 1
        fi
    done
    
    log_success "依赖项检查完成"
}

create_backup() {
    log_info "创建备份到: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Backup critical files
    cp -r "$FRIDA_GUM_DIR/gum/gum.c" "$BACKUP_DIR/" 2>/dev/null || true
    cp -r "$FRIDA_CORE_DIR/lib/base/rpc.vala" "$BACKUP_DIR/" 2>/dev/null || true
    cp -r "$FRIDA_CORE_DIR/src/linux/linux-host-session.vala" "$BACKUP_DIR/" 2>/dev/null || true
    cp -r "$FRIDA_CORE_DIR/src/frida-glue.c" "$BACKUP_DIR/" 2>/dev/null || true
    
    log_success "备份创建完成"
}

apply_program_name_patch() {
    log_info "应用增强程序名补丁..."
    
    # Enhanced program name patch for gum.c
    cat > /tmp/enhanced_gum_patch.c << 'EOF'
  // Enhanced: Generate dynamic program name to avoid detection
  {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static const char prefixes[][8] = {"sys", "lib", "net", "dev", "usr", "bin", "app"};
    char dynamic_name[32];
    time_t t = time(NULL);
    srand(t ^ getpid());
    
    int prefix_idx = rand() % (sizeof(prefixes) / sizeof(prefixes[0]));
    int suffix_len = 4 + (rand() % 6); // 4-9 chars
    snprintf(dynamic_name, sizeof(dynamic_name), "%s", prefixes[prefix_idx]);
    int base_len = strlen(dynamic_name);
    for (int i = 0; i < suffix_len && (base_len + i) < 31; i++)
      dynamic_name[base_len + i] = charset[rand() % (sizeof(charset) - 1)];
    dynamic_name[base_len + suffix_len] = '\0';
    g_set_prgname(dynamic_name);
  }
EOF
    
    # Apply to gum.c
    sed -i 's/g_set_prgname ("frida");/\/\/ Enhanced program name generation/' "$FRIDA_GUM_DIR/gum/gum.c"
    sed -i '/\/\/ Enhanced program name generation/r /tmp/enhanced_gum_patch.c' "$FRIDA_GUM_DIR/gum/gum.c"
    
    # Apply to frida-glue.c
    if [[ -f "$FRIDA_CORE_DIR/src/frida-glue.c" ]]; then
        sed -i 's/g_set_prgname ("ggbond");/\/\/ Enhanced program name generation/' "$FRIDA_CORE_DIR/src/frida-glue.c"
        sed -i '/\/\/ Enhanced program name generation/r /tmp/enhanced_gum_patch.c' "$FRIDA_CORE_DIR/src/frida-glue.c"
    fi
    
    rm -f /tmp/enhanced_gum_patch.c
    log_success "程序名补丁应用完成"
}

apply_rpc_protocol_patch() {
    log_info "应用增强 RPC 协议补丁..."
    
    # Create enhanced RPC patch
    cat > /tmp/enhanced_rpc_functions.vala << 'EOF'
		private static string obfuscated_protocol_id = null;
		private static uint8 xor_key = 0;

		private string get_rpc_protocol_id(bool quote) {
			if (obfuscated_protocol_id == null) {
				// Enhanced: Generate dynamic protocol ID
				var now = new DateTime.now_local();
				var seed = (uint32)(now.to_unix() & 0xFFFFFFFF);
				Random.set_seed(seed ^ (uint32)Posix.getpid());
				
				var base_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				var protocol_parts = new string[3];
				
				var prefix_len = Random.int_range(3, 6);
				var prefix = new StringBuilder();
				for (int i = 0; i < prefix_len; i++) {
					prefix.append_c(base_chars[Random.int_range(0, base_chars.length)]);
				}
				protocol_parts[0] = prefix.str;
				
				var time_component = "%04x".printf((uint16)(seed & 0xFFFF));
				protocol_parts[1] = time_component;
				
				var suffix_len = Random.int_range(2, 5);
				var suffix = new StringBuilder();
				for (int i = 0; i < suffix_len; i++) {
					suffix.append_c(base_chars[Random.int_range(0, base_chars.length)]);
				}
				protocol_parts[2] = suffix.str;
				
				obfuscated_protocol_id = string.joinv(":", protocol_parts);
			}
			
			return quote ? "\"%s\"".printf(obfuscated_protocol_id) : obfuscated_protocol_id;
		}
EOF
    
    # Apply to rpc.vala
    sed -i '/Object (peer: peer);/r /tmp/enhanced_rpc_functions.vala' "$FRIDA_CORE_DIR/lib/base/rpc.vala"
    sed -i 's/"frida:rpc"/get_rpc_protocol_id(false)/g' "$FRIDA_CORE_DIR/lib/base/rpc.vala"
    sed -i 's/"\"frida:rpc\""/get_rpc_protocol_id(true)/g' "$FRIDA_CORE_DIR/lib/base/rpc.vala"
    
    rm -f /tmp/enhanced_rpc_functions.vala
    log_success "RPC 协议补丁应用完成"
}

apply_agent_filename_patch() {
    log_info "应用增强 agent 文件名补丁..."
    
    # Create enhanced agent filename function
    cat > /tmp/enhanced_agent_function.vala << 'EOF'
			// Enhanced: Generate more realistic library names
			string generate_realistic_lib_name() {
				var lib_prefixes = new string[] {
					"lib", "android", "system", "native", "core", "base", "util",
					"media", "graphics", "ui", "net", "crypto", "ssl", "dbus"
				};
				var lib_suffixes = new string[] {
					"core", "base", "util", "helper", "service", "client", "engine",
					"manager", "handler", "worker", "bridge", "proxy", "cache"
				};
				
				var now = new DateTime.now_local();
				Random.set_seed((uint32)(now.to_unix() ^ Posix.getpid()));
				
				var prefix = lib_prefixes[Random.int_range(0, lib_prefixes.length)];
				var suffix = lib_suffixes[Random.int_range(0, lib_suffixes.length)];
				var version = Random.int_range(1, 99);
				
				return "%s%s%02d".printf(prefix, suffix, version);
			}
			
			var realistic_name = generate_realistic_lib_name();
EOF
    
    # Apply to linux-host-session.vala
    if [[ -f "$FRIDA_CORE_DIR/src/linux/linux-host-session.vala" ]]; then
        sed -i '/var emulated_arm64 = /r /tmp/enhanced_agent_function.vala' "$FRIDA_CORE_DIR/src/linux/linux-host-session.vala"
        sed -i 's/var random_prefix = GLib.Uuid.string_random();/\/\/ Enhanced agent filename generation applied above/' "$FRIDA_CORE_DIR/src/linux/linux-host-session.vala"
        sed -i 's/random_prefix/realistic_name/g' "$FRIDA_CORE_DIR/src/linux/linux-host-session.vala"
    fi
    
    rm -f /tmp/enhanced_agent_function.vala
    log_success "Agent 文件名补丁应用完成"
}

setup_enhanced_anti_detection() {
    log_info "设置增强反检测脚本..."
    
    # Copy enhanced anti-detection script
    cp "$ENHANCED_PATCHES_DIR/0008-enhanced-anti-detection.py" "$FRIDA_CORE_DIR/src/enhanced-anti-detection.py"
    cp "$ENHANCED_PATCHES_DIR/obfuscation_config.json" "$FRIDA_CORE_DIR/src/obfuscation_config.json"
    chmod +x "$FRIDA_CORE_DIR/src/enhanced-anti-detection.py"
    
    # Modify embed-agent.py to use enhanced script
    if [[ -f "$FRIDA_CORE_DIR/src/embed-agent.py" ]]; then
        sed -i '/embedded_agent.write_bytes(b"")/a \
            import os\
            enhanced_script = str(output_dir) + "/../../../../frida/subprojects/frida-core/src/enhanced-anti-detection.py"\
            return_code = os.system("python3 " + enhanced_script + " " + str(priv_dir / f"frida-agent-{flavor}.so"))\
            if return_code == 0:\
                print("Enhanced anti-detection completed successfully")\
            else:\
                print("Enhanced anti-detection error. Code:", return_code)' "$FRIDA_CORE_DIR/src/embed-agent.py"
    fi
    
    log_success "增强反检测脚本设置完成"
}

apply_additional_patches() {
    log_info "应用其他增强补丁..."
    
    # Symbol obfuscation in various files
    find "$FRIDA_CORE_DIR" -name "*.vala" -exec sed -i 's/"frida_agent_main"/"main"/g' {} \;
    find "$FRIDA_CORE_DIR" -name "*.vala" -exec sed -i 's/frida_agent_main/main/g' {} \;
    
    # Memory file descriptor name obfuscation
    if [[ -f "$FRIDA_CORE_DIR/src/linux/frida-helper-backend.vala" ]]; then
        sed -i 's/Linux.syscall (SysCall.memfd_create, name, flags);/Linux.syscall (SysCall.memfd_create, "jit-cache", flags);/' "$FRIDA_CORE_DIR/src/linux/frida-helper-backend.vala"
    fi
    
    # Protocol error handling
    if [[ -f "$FRIDA_CORE_DIR/src/droidy/droidy-client.vala" ]]; then
        sed -i 's/throw new Error.PROTOCOL ("Unexpected command");/break; \/\/ Enhanced: Silent handling of unexpected commands/' "$FRIDA_CORE_DIR/src/droidy/droidy-client.vala"
    fi
    
    log_success "其他增强补丁应用完成"
}

verify_patches() {
    log_info "验证补丁应用..."
    
    local errors=0
    
    # Check if key modifications are in place
    if ! grep -q "dynamic_name" "$FRIDA_GUM_DIR/gum/gum.c"; then
        log_error "程序名补丁验证失败"
        ((errors++))
    fi
    
    if ! grep -q "get_rpc_protocol_id" "$FRIDA_CORE_DIR/lib/base/rpc.vala"; then
        log_error "RPC 协议补丁验证失败"
        ((errors++))
    fi
    
    if [[ -f "$FRIDA_CORE_DIR/src/enhanced-anti-detection.py" ]]; then
        log_success "增强反检测脚本已安装"
    else
        log_error "增强反检测脚本安装失败"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "所有补丁验证通过"
    else
        log_error "发现 $errors 个验证错误"
        return 1
    fi
}

print_summary() {
    echo
    echo "======================================"
    echo -e "${GREEN}增强 Florida 补丁应用完成${NC}"
    echo "======================================"
    echo
    echo "应用的增强功能:"
    echo "✓ 动态程序名生成"
    echo "✓ 高级 RPC 协议混淆"
    echo "✓ 智能 Agent 文件名伪装"
    echo "✓ 符号混淆增强"
    echo "✓ 内存布局混淆"
    echo "✓ 增强反检测脚本"
    echo "✓ 错误处理改进"
    echo "✓ 配置化支持"
    echo
    echo "备份位置: $BACKUP_DIR"
    echo "配置文件: $FRIDA_CORE_DIR/src/obfuscation_config.json"
    echo
    echo "下一步: 编译 frida 以生成增强版本"
    echo "命令: ./releng/frida-env.py build"
    echo
}

main() {
    echo -e "${BLUE}Enhanced Florida Patches Auto-Apply Script${NC}"
    echo "=========================================="
    echo
    
    check_dependencies
    create_backup
    
    apply_program_name_patch
    apply_rpc_protocol_patch
    apply_agent_filename_patch
    setup_enhanced_anti_detection
    apply_additional_patches
    
    if verify_patches; then
        print_summary
        log_success "所有增强补丁应用成功！"
        exit 0
    else
        log_error "补丁应用过程中出现错误"
        exit 1
    fi
}

# Run main function
main "$@" 