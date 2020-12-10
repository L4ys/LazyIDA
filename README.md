# LazyIDA
Make your IDA Lazy!

# Install
1. put `LazyIDA.py` into `plugins` folder under your IDA Pro installation path.

# Features
- Jump to other based-address without rebase the idb.
![](https://a123-1304302739.cos.ap-chengdu.myqcloud.com/%7BCC12AA66-0AAC-585B-09FD-FD50E90FE957%7D.jpg)

When you debug a program using ohter debuggers, such as ollydbg, and you want to jump to some runtime address in ida, but the imagebase had changed sometimes, so the only way is to rebase idb and type 'G' to jump to the target address. For some large program's idb, it will takes terrible time to rebase the idb.

offset = target_addr - target_base + currrent_base

LazyIDA can help you jump to other based-address without rebase.
shortcuts:
Shift + G, LazyIDA will copy the address from clipboard, and fill it in 'Target Addr'.


  - Remove function return type in Hex-Rays:
  
![2016-06-12 11 05 29](https://cloud.githubusercontent.com/assets/5360374/15991889/2dad5d62-30f2-11e6-8d4b-e4efb0b73c77.png)

  - Convert data into different formats:
  
![2016-06-12 11 01 57](https://cloud.githubusercontent.com/assets/5360374/15991854/b813070a-30f1-11e6-931e-08ae85355cca.png)
![2016-06-12 11 03 18](https://cloud.githubusercontent.com/assets/5360374/15991863/e5271146-30f1-11e6-89ac-bafd46eb1e45.png)
  - Scan for format string vulnerabilities:
  
![2016-06-15 8 19 03](https://cloud.githubusercontent.com/assets/5360374/16064234/da39aa8c-32d1-11e6-89b8-1709cef270f5.png)
  - Jump to vtable functions by double clicking
  - Lazy shortcuts:
    - Disasm Window: 
      - `w`: Copy address of current line into clipboard
    - Hex-rays Window: 
      - `w`: Copy address of current item into clipboard
      - `c`: Copy name of current item into clipboard
      - `v`: Remove return type of current item

  - paste data to arbitary address, supports paste from HEX, BASE64, or ASCII

![](https://x1hy9.oss-cn-beijing.aliyuncs.com/img/%7B604FF5B0-723B-943A-B34A-DA2E2D7B6D91%7D.jpg)
  - lazy dumper, A tool for dump  memory to a file, you can specify it size in ui.

![](https://x1hy9.oss-cn-beijing.aliyuncs.com/img/%7B9ED5EC0D-3338-0CA6-EB59-7414CFB9C4E8%7D.jpg)
  