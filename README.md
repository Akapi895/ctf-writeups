# CTF Writeups

Repository chứa các writeup về các thử thách CTF (Capture The Flag) mà tôi đã hoàn thành.

## 📚 Nội dung

### HackTheBox

- **[Machines](./HackTheBox/Machines/)** - Writeups cho các máy (machine) trên HackTheBox
- **[Modules](./HackTheBox/Modules/)** - Writeups cho các module học tập trên HackTheBox

### CTF Competitions

Các writeup cho các cuộc thi CTF tôi đã tham gia sẽ được tổ chức theo từng folder riêng.

### Scripts

Các script hữu ích và công cụ tự động hóa được sử dụng trong quá trình giải CTF. Xem thêm tại [Scripts/README.md](./Scripts/README.md)

## 🏗️ Cấu trúc thư mục

```
ctf-writeups/
├── HackTheBox/
│   ├── Machines/
│   │   └── [Tên-Machine]/
│   │       └── README.md
│   └── Modules/
│       └── [Tên-Module]/
│           └── README.md
├── [Tên-CTF-Competition]/
│   ├── Challenge-1/
│   │   └── README.md
│   └── Challenge-2/
│       └── README.md
└── Scripts/
    ├── README.md
    └── [các-script.py/sh]
```

## 📝 Template cho Writeup

Mỗi writeup nên bao gồm:

### HackTheBox Machine

````markdown
# [Tên Machine]

## Thông tin

- **Độ khó:** [Easy/Medium/Hard/Insane]
- **OS:** [Linux/Windows/Other]
- **IP:** [IP Address]
- **Ngày hoàn thành:** [DD/MM/YYYY]

## Tóm tắt

Mô tả ngắn gọn về machine và phương pháp tấn công chính.

## Reconnaissance

### Nmap Scan

```bash
[Kết quả scan]
```
````

### Enumeration

[Chi tiết quá trình thu thập thông tin]

## Initial Foothold

[Cách thức khai thác để có được quyền truy cập ban đầu]

## Privilege Escalation

[Cách thức leo thang đặc quyền để có root/administrator]

## Flags

- **User Flag:** `[hash]`
- **Root Flag:** `[hash]`

## Lessons Learned

[Những bài học và kỹ thuật quan trọng]

## Tools Used

- [Tool 1]
- [Tool 2]

````

### HackTheBox Module
```markdown
# [Tên Module]

## Thông tin
- **Chủ đề:** [Topic]
- **Độ khó:** [Easy/Medium/Hard]
- **Ngày hoàn thành:** [DD/MM/YYYY]

## Tóm tắt
Tổng quan về module và những gì học được.

## Sections
### [Section 1]
[Nội dung và ghi chú]

### [Section 2]
[Nội dung và ghi chú]

## Skills & Techniques
- [Kỹ năng 1]
- [Kỹ năng 2]

## Key Takeaways
[Những điểm chính cần ghi nhớ]
````

### CTF Challenge

```markdown
# [Tên Challenge]

## Thông tin

- **CTF:** [Tên cuộc thi]
- **Category:** [Web/Pwn/Reverse/Crypto/Forensics/Misc]
- **Points:** [Điểm]
- **Solves:** [Số đội giải được]

## Description

[Mô tả challenge]

## Solution

[Chi tiết cách giải]

## Flag
```

[flag]

```

## Tools/Scripts
[Các công cụ và script sử dụng]
```

## 🛠️ Công cụ thường dùng

- **Reconnaissance:** nmap, masscan, rustscan
- **Web:** Burp Suite, ffuf, gobuster, sqlmap
- **Exploitation:** metasploit, exploit-db
- **Privilege Escalation:** linpeas, winpeas, GTFOBins
- **Reverse Engineering:** Ghidra, IDA, radare2
- **Cryptography:** CyberChef, RsaCtfTool
- **Forensics:** Wireshark, binwalk, volatility

## 📖 Tài nguyên tham khảo

- [HackTheBox](https://www.hackthebox.com/)
- [CTFtime](https://ctftime.org/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [GTFOBins](https://gtfobins.github.io/)

## 📫 Liên hệ

Nếu có câu hỏi hoặc muốn thảo luận về các writeup, vui lòng mở issue hoặc liên hệ qua:

- GitHub: [@Akapi895](https://github.com/Akapi895)

## ⚠️ Disclaimer

Các writeup này chỉ dành cho mục đích học tập và nghiên cứu. Vui lòng chỉ sử dụng các kỹ thuật được mô tả trong môi trường hợp pháp và có sự cho phép.

---

**Happy Hacking! 🚩**
