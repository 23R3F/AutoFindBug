基于angr做的漏洞自动挖掘python程序

目前仅能完python程序成简单程序的漏洞挖掘，仅在Ubuntu1604下测试64位elf

能漏洞类型有：栈溢出、格式化字符串（仅printf函数）、uaf/double_free（仅libc2.23下的malloc和free）、任意地址读写、寄存器错误