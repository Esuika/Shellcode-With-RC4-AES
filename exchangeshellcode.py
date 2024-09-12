import re

def shellcode_to_hexlist(shellcode):
    # 将 \x 格式的 shellcode 转换为 0x 格式
    hex_values = re.findall(r'\\x([0-9a-fA-F]{2})', shellcode)  # 提取每个 \x 后的两个十六进制数字
    hex_list = ["0x" + hex_value for hex_value in hex_values]  # 组合成 0x 格式
    return ', '.join(hex_list)

def hexlist_to_shellcode(hex_list):
    # 将 0x 格式的 shellcode 转换为 \x 格式
    hex_values = re.findall(r'0x([0-9a-fA-F]{2})', hex_list)  # 提取每个 0x 后的两个十六进制数字
    shellcode = ''.join([f"\\x{hex_value}" for hex_value in hex_values])  # 组合成 \x 格式
    return shellcode

def main():
    print("请选择要进行的操作：")
    print("[1] 将 \\x 格式的 shellcode 转换为 0x 格式")
    print("[2] 将 0x 格式的 shellcode 转换为 \\x 格式")
    
    choice = input("请输入选项 (1 或 2): ")

    if choice == "1":
        shellcode = input("请输入原始 \\x 格式 shellcode: ")
        converted = shellcode_to_hexlist(shellcode)
        print(f"转换后的 0x 格式 shellcode:\n{converted}")
    elif choice == "2":
        hexlist = input("请输入原始 0x 格式 shellcode (用逗号分隔): ")
        converted = hexlist_to_shellcode(hexlist)
        print(f"转换后的 \\x 格式 shellcode:\n{converted}")
    else:
        print("无效的选项，请重新运行程序并选择 1 或 2。")

if __name__ == "__main__":
    main()
