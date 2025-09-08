#!/usr/bin/env python3
"""
IMX Firmware IVT (Image Vector Table) Parser
Searches for IVT magic bytes and parses the IVT structure
Supports multiple IVTs in a single firmware file with image extraction
"""

import sys
import struct
import argparse
import os
from typing import Optional, List, Dict, Tuple

class IVTParser:
    # IVT magic bytes patterns
    MAGIC_PATTERNS = [
        b'\xD1\x00\x20\x40',  # IVT magic: 0xD1 0x00 0x20 0x40
        b'\xD1\x00\x20\x41'   # IVT magic: 0xD1 0x00 0x20 0x41
    ]
    
    # IVT structure size (32 bytes)
    IVT_SIZE = 32

    BOOT_DATA_STRUCTURE_SIZE = 32
    
    def __init__(self, filename: str):
        self.filename = filename
        self.data = None
        
    def load_file(self) -> bool:
        """Load firmware file into memory"""
        try:
            with open(self.filename, 'rb') as f:
                self.data = f.read()
            print(f"Loaded firmware file: {self.filename} ({len(self.data)} bytes)")
            return True
        except FileNotFoundError:
            print(f"Error: File '{self.filename}' not found")
            return False
        except IOError as e:
            print(f"Error reading file: {e}")
            return False
    
    def find_all_ivt_offsets(self) -> List[int]:
        """Find all offsets of IVT magic bytes in the firmware"""
        if not self.data:
            return []
        
        offsets = []
        for pattern in self.MAGIC_PATTERNS:
            start = 0
            while True:
                offset = self.data.find(pattern, start)
                if offset == -1:
                    break
                offsets.append(offset)
                start = offset + 1  # Continue searching after this occurrence
        
        # Sort offsets and remove duplicates
        offsets = sorted(list(set(offsets)))
        return offsets
    
    def parse_ivt(self, offset: int) -> Optional[Dict]:
        """Parse IVT structure starting at given offset"""
        if not self.data or offset + self.IVT_SIZE > len(self.data):
            print(f"Error: Not enough data to parse complete IVT at offset 0x{offset:08X}")
            return None
        
        # Extract IVT data
        ivt_data = self.data[offset:offset + self.IVT_SIZE]
        
        try:
            # Parse IVT structure (little-endian)
            # IVT structure (32 bytes total):
            # 0x00: Header (4 bytes) - magic + length + version
            # 0x04: Entry point (4 bytes)
            # 0x08: Reserved1 (4 bytes)
            # 0x0C: DCD pointer (4 bytes)
            # 0x10: Boot data pointer (4 bytes)
            # 0x14: Self pointer (4 bytes)
            # 0x18: CSF pointer (4 bytes)
            # 0x1C: Reserved2 (4 bytes)
            
            ivt_struct = struct.unpack('<8I', ivt_data)
            
            # Parse header field
            header = ivt_struct[0]
            magic = header & 0xFF
            length_raw = (header >> 8) & 0xFFFF
            length = ((length_raw & 0xFF) << 8) | ((length_raw >> 8) & 0xFF)  # Swap bytes
            version = (header >> 24) & 0xFF
            
            ivt_info = {
                'offset': offset,
                'header': {
                    'magic': magic,
                    'length': length,
                    'version': version,
                    'raw': header
                },
                'entry_point': ivt_struct[1],
                'reserved1': ivt_struct[2],
                'dcd_pointer': ivt_struct[3],
                'boot_data_pointer': ivt_struct[4],
                'self_pointer': ivt_struct[5],
                'csf_pointer': ivt_struct[6],
                'reserved2': ivt_struct[7]
            }
            
            return ivt_info
            
        except struct.error as e:
            print(f"Error parsing IVT structure at offset 0x{offset:08X}: {e}")
            return None

    
       


    def extract_boot_data_struct(self, ivt_info: Dict):
            ivt_self_pointer = ivt_info['self_pointer']
            boot_pointer = ivt_info['boot_data_pointer']
            ivt_offset =  ivt_info['offset']

            ## How far is the boot data structure from the IVT?
            boot_offset_from_ivt =  ivt_info['boot_data_pointer'] - ivt_info['self_pointer']
            ## How far is the boot data structure from the beginning of the file ?
            boot_offset_from_beginning_of_file = ivt_offset+boot_offset_from_ivt

            boot_data_struct_raw = self.data[boot_offset_from_beginning_of_file:boot_offset_from_beginning_of_file + self.BOOT_DATA_STRUCTURE_SIZE]


                
            boot_data_struct_unpacked = struct.unpack('<8I', boot_data_struct_raw)
                

                
            boot_data_struct = {
                    'offset': boot_offset_from_beginning_of_file,
                    'start': boot_data_struct_unpacked[0],
                    'length': boot_data_struct_unpacked[1],
                    'plugin': boot_data_struct_unpacked[2]

            }
            
        
          
            
            return boot_data_struct


        


    
    def print_ivt_info(self, ivt_info: Dict, ivt_number: int = 1, output_dir: str = "extracted"):
        """Print formatted IVT information"""
        print("\n" + "="*60)
        print(f"IMX FIRMWARE IVT #{ivt_number} (Image Vector Table)")
        print("="*60)
        
        print(f"\nIVT found at offset: 0x{ivt_info['offset']:08X}")
        print(f"File: {self.filename}")
        
        print(f"\nHeader:")
        print(f"  Raw value:        0x{ivt_info['header']['raw']:08X}")
        print(f"  Magic byte:       0x{ivt_info['header']['magic']:02X}")
        print(f"  Length:           0x{ivt_info['header']['length']:02X} ")
        print(f"  Version:          0x{ivt_info['header']['version']:02X}")
        
        print(f"\nIVT Structure:")
        print(f"  Entry Point:      0x{ivt_info['entry_point']:08X}")
        print(f"  Reserved1:        0x{ivt_info['reserved1']:08X}")
        print(f"  DCD Pointer:      0x{ivt_info['dcd_pointer']:08X}")
        print(f"  Boot Data Ptr:    0x{ivt_info['boot_data_pointer']:08X}")
        print(f"  Self Pointer:     0x{ivt_info['self_pointer']:08X}")
        print(f"  CSF Pointer:      0x{ivt_info['csf_pointer']:08X}")
        print(f"  Reserved2:        0x{ivt_info['reserved2']:08X}")
        
     
                
      
        extracted = self.extract_boot_data_struct(ivt_info)
        print(f"\n  Boot Data Structure:")
        print(f"    Start:      0x{extracted['start']:08X}")
        print(f"    Length:     0x{extracted['length']:08X}")
        if extracted['plugin']:
            print(f"    Plugin:     True")
        else:
            print(f"    Plugin:     False")
        print()
           

          
        

           # Additional analysis
        if ivt_info['entry_point'] != 0:
            print(f"  - Application entry point: 0x{ivt_info['entry_point']:08X}")
        if ivt_info['dcd_pointer'] != 0:
            print(f"  - DCD (Device Configuration Data) present")
        if ivt_info['csf_pointer'] != 0:
            print(f"  - CSF (Command Sequence File) present - signed image")
        else:
            print(f"  - No CSF - unsigned image")
        if extracted['plugin']:
            print("""  - Plugin Boot Data: "The boot ROM detects the image type using the plugin flag of the boot data structure. If the plugin flag is 1, then the ROM uses the image as a plugin function. 
The function must initialize the boot device and copy the program image to the final location. At the end, the plugin function must return with the program image parameters."
""")
        print("""  - Note when booting from MCC/SD/eSD/SDXC/eMMC:  "The MMC/SD/eSD/SDXC/eMMC can be connected to any of the USDHC blocks and can be booted by copying 4 KB of data from the MMC/SD/eSD/eMMC device to the internal RAM. 
After checking the Image Vector Table header value (0xD1) from program image, the ROM code performs a DCD check.
After a successful DCD extraction, the ROM code extracts from the Boot Data Structure the destination pointer and length of image to be copied to the RAM device from where the code execution occurs."
""")

        print("="*60)
    
    def print_summary(self, all_ivts: List[Dict]):
        """Print a summary of all found IVTs"""
        print(f"\n" + "="*60)
        print(f"SUMMARY: Found {len(all_ivts)} IVT(s) in firmware")
        print("="*60)
        
        for i, ivt_info in enumerate(all_ivts, 1):
            print(f"IVT #{i}:")
            print(f"  Offset:      0x{ivt_info['offset']:08X}")
            print(f"  Entry Point: 0x{ivt_info['entry_point']:08X}")
            print(f"  Signed:      {'Yes' if ivt_info['csf_pointer'] != 0 else 'No'}")
            print(f"  DCD:         {'Present' if ivt_info['dcd_pointer'] != 0 else 'None'}")
            print()
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="IMX Firmware IVT (Image Vector Table) Parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script searches for IMX IVT magic bytes (0xD1 0x00 0x20 0x40/0x41)
and parses all Image Vector Table structures found in the firmware.

Examples:
  python ivt_parser.py firmware.bin           # Parse IVTs only
        """
    )
    
    parser.add_argument('firmware_file', help='IMX firmware file to analyze')

    # parser.add_argument('-o', '--output-dir', default='extracted',
    #                    help='Output directory for extracted images (default: extracted)')
    
    args = parser.parse_args()
    
    # Create parser instance
    ivt_parser = IVTParser(args.firmware_file)
    
    # Load firmware file
    if not ivt_parser.load_file():
        sys.exit(1)
    
    print("Searching for IVT magic bytes...")
    
    # Find all IVT offsets
    ivt_offsets = ivt_parser.find_all_ivt_offsets()
    if not ivt_offsets:
        print("No IVT magic bytes found in firmware")
        sys.exit(1)
    
    print(f"Found {len(ivt_offsets)} IVT(s) at offsets: {[hex(offset) for offset in ivt_offsets]}")
    
    # Parse all IVTs
    all_ivts = []
    for i, offset in enumerate(ivt_offsets, 1):
        print(f"\nProcessing IVT #{i} at offset 0x{offset:08X}...")
        ivt_info = ivt_parser.parse_ivt(offset)
        if ivt_info:
            all_ivts.append(ivt_info)
        else:
            print(f"Failed to parse IVT #{i}")
    
    if not all_ivts:
        print("No valid IVTs could be parsed")
        sys.exit(1)
    
    # Display summary first
    ivt_parser.print_summary(all_ivts)
    
    # Display detailed information for each IVT
    for i, ivt_info in enumerate(all_ivts, 1):
        ivt_parser.print_ivt_info(ivt_info, i)


if __name__ == "__main__":
    main()