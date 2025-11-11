# Scripts & Tools

Tập hợp các script và công cụ tự tạo để hỗ trợ trong quá trình giải CTF.

## 📁 Danh sách Scripts

### Reconnaissance

- **port_scanner.py** - Script scan port nhanh
- **subdomain_enum.py** - Tìm kiếm subdomain
- **directory_bruteforce.py** - Brute force directory/file

### Web Exploitation

- **sqli_automated.py** - Automated SQL injection testing
- **xss_payload_generator.py** - Tạo XSS payload
- **web_fuzzer.py** - Fuzzing web parameters

### Cryptography

- **caesar_cipher.py** - Mã hóa/giải mã Caesar cipher
- **rsa_attack.py** - Các kiểu tấn công RSA phổ biến
- **xor_bruteforce.py** - Brute force XOR key

### Reverse Engineering

- **string_extractor.py** - Trích xuất strings từ binary
- **deobfuscator.py** - Deobfuscate code
- **assembly_helper.py** - Utilities cho assembly analysis

### Forensics

- **file_carver.py** - Khôi phục file từ dump
- **metadata_extractor.py** - Trích xuất metadata
- **steganography_detector.py** - Phát hiện steganography

### Pwn/Binary Exploitation

- **rop_chain_builder.py** - Tạo ROP chain
- **shellcode_generator.py** - Tạo shellcode
- **buffer_overflow_helper.py** - Utilities cho buffer overflow

### Post-Exploitation

- **reverse_shell_listener.py** - Listener cho reverse shell
- **privilege_checker.py** - Kiểm tra privilege escalation vectors
- **persistence_helper.py** - Script tạo persistence

### Utilities

- **ctf_template_generator.py** - Tạo template writeup tự động
- **flag_finder.py** - Tìm kiếm flag trong text/files
- **hash_identifier.py** - Nhận dạng loại hash
- **base_converter.py** - Chuyển đổi giữa các hệ cơ số

## 🚀 Hướng dẫn sử dụng

### Cài đặt Dependencies

```bash
pip install -r requirements.txt
```

### Ví dụ sử dụng

#### Port Scanner

```bash
python port_scanner.py -t <target_ip> -p <port_range>
```

#### SQL Injection Tester

```bash
python sqli_automated.py -u <url> -p <parameter>
```

#### XOR Bruteforce

```bash
python xor_bruteforce.py -f <encrypted_file>
```

## 📦 Requirements

```
requests
pwntools
scapy
beautifulsoup4
colorama
argparse
```

## 🔧 Phát triển

Khi thêm script mới:

1. Đặt tên file mô tả rõ chức năng
2. Thêm docstring và comments
3. Include argument parser cho dễ sử dụng
4. Cập nhật README này
5. Thêm vào requirements.txt nếu có dependencies mới

### Template Script cơ bản

```python
#!/usr/bin/env python3
"""
Script Name: [Tên script]
Description: [Mô tả chức năng]
Author: [Tên]
Date: [Ngày tạo]
"""

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='[Mô tả]')
    parser.add_argument('-t', '--target', required=True, help='Target input')
    parser.add_argument('-o', '--output', help='Output file (optional)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Main logic here
    if args.verbose:
        print(f"[*] Processing {args.target}...")

    # Your code here

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user")
        sys.exit(1)
```

## 💡 Best Practices

1. **Modular Code**: Tách functions thành modules có thể tái sử dụng
2. **Error Handling**: Luôn handle exceptions properly
3. **Logging**: Sử dụng logging thay vì print statements
4. **Documentation**: Comment code và viết docstrings
5. **Testing**: Test script trước khi commit

## 🎯 Roadmap

- [ ] Tích hợp với API HackTheBox
- [ ] Tạo automation framework cho CTF
- [ ] Thêm machine learning cho pattern recognition
- [ ] Build web dashboard để quản lý scripts
- [ ] Tạo Docker container với all tools

## 📚 Tài liệu tham khảo

- [Python Documentation](https://docs.python.org/3/)
- [Pwntools](https://docs.pwntools.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## ⚠️ Disclaimer

Các script này chỉ nên được sử dụng trong môi trường hợp pháp và có sự cho phép. Tác giả không chịu trách nhiệm về việc sử dụng sai mục đích.

---

**Happy Scripting! 🐍**
