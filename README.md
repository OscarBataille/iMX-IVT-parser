# iMX-IVT-parser
Parse the Image Vector Tables of i.MX 6 firmwares.
The Boot Data Structure address provides the offset needed to import the firmware in a Reverse Engineering tool like Ghidra.

## How to use

```bash
oscar@LAPTOP-O36CJECO:~/iMX-IVT-parser$ python3 script.py ../kindle/outpiut/imx6sll_rex/u-boot.bin
Loaded firmware file: ../kindle/outpiut/imx6sll_rex/u-boot.bin (519168 bytes)
Searching for IVT magic bytes...
Found 2 IVT(s) at offsets: ['0x0', '0x4000']

Processing IVT #1 at offset 0x00000000...

Processing IVT #2 at offset 0x00004000...

============================================================
SUMMARY: Found 2 IVT(s) in firmware
============================================================
IVT #1:
  Offset:      0x00000000
  Entry Point: 0x0090842C
  Signed:      Yes
  DCD:         None

IVT #2:
  Offset:      0x00004000
  Entry Point: 0x87800000
  Signed:      Yes
  DCD:         None

============================================================

============================================================
IMX FIRMWARE IVT #1 (Image Vector Table)
============================================================

IVT found at offset: 0x00000000
File: ../kindle/outpiut/imx6sll_rex/u-boot.bin

Header:
  Raw value:        0x402000D1
  Magic byte:       0xD1
  Length:           0x20
  Version:          0x40

IVT Structure:
  Entry Point:      0x0090842C
  Reserved1:        0x00000000
  DCD Pointer:      0x00000000
  Boot Data Ptr:    0x00908420
  Self Pointer:     0x00908400
  CSF Pointer:      0x0090A400
  Reserved2:        0x00000000

  Boot Data Structure:
    Start:      0x00908000
    Length:     0x00008000
    Plugin:     True

  - Application entry point: 0x0090842C
  - CSF (Command Sequence File) present - signed image
  - Plugin Boot Data: "The boot ROM detects the image type using the plugin flag of the boot data structure. If the plugin flag is 1, then the ROM uses the image as a plugin function.
The function must initialize the boot device and copy the program image to the final location. At the end, the plugin function must return with the program image parameters."

  - Note when booting from MCC/SD/eSD/SDXC/eMMC:  "The MMC/SD/eSD/SDXC/eMMC can be connected to any of the USDHC blocks and can be booted by copying 4 KB of data from the MMC/SD/eSD/eMMC device to the internal RAM.
After checking the Image Vector Table header value (0xD1) from program image, the ROM code performs a DCD check.
After a successful DCD extraction, the ROM code extracts from the Boot Data Structure the destination pointer and length of image to be copied to the RAM device from where the code execution occurs."

============================================================

============================================================
IMX FIRMWARE IVT #2 (Image Vector Table)
============================================================

IVT found at offset: 0x00004000
File: ../kindle/outpiut/imx6sll_rex/u-boot.bin

Header:
  Raw value:        0x402000D1
  Magic byte:       0xD1
  Length:           0x20
  Version:          0x40

IVT Structure:
  Entry Point:      0x87800000
  Reserved1:        0x00000000
  DCD Pointer:      0x00000000
  Boot Data Ptr:    0x877FFFF4
  Self Pointer:     0x877FFFD4
  CSF Pointer:      0x87878BD4
  Reserved2:        0x00000000

  Boot Data Structure:
    Start:      0x877FBBD4
    Length:     0x0007F000
    Plugin:     False

  - Application entry point: 0x87800000
  - CSF (Command Sequence File) present - signed image
  - Note when booting from MCC/SD/eSD/SDXC/eMMC:  "The MMC/SD/eSD/SDXC/eMMC can be connected to any of the USDHC blocks and can be booted by copying 4 KB of data from the MMC/SD/eSD/eMMC device to the internal RAM.
After checking the Image Vector Table header value (0xD1) from program image, the ROM code performs a DCD check.
After a successful DCD extraction, the ROM code extracts from the Boot Data Structure the destination pointer and length of image to be copied to the RAM device from where the code execution occurs."

============================================================
```
