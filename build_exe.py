#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build script for creating portable executable with PyInstaller
"""

import subprocess
import sys
import shutil
from pathlib import Path

def clean_build_folders():
    """Remove previous build artifacts"""
    print("🧹 Cleaning previous build artifacts...")
    folders_to_remove = ['build', 'dist', '__pycache__']
    
    for folder in folders_to_remove:
        folder_path = Path(folder)
        if folder_path.exists():
            shutil.rmtree(folder_path)
            print(f"   ✓ Removed {folder}/")
    
    # Remove .spec file if exists
    spec_file = Path('main.spec')
    if spec_file.exists():
        spec_file.unlink()
        print(f"   ✓ Removed main.spec")
    
    print()

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building portable executable...")
    print()
    
    # PyInstaller command
    command = [
        sys.executable,
        '-m', 'PyInstaller',
        '--onefile',                    # Single executable file
        '--console',                    # Console application
        '--name', 'PacketSniffer',      # Output name
        '--clean',                      # Clean cache
        '--noconfirm',                  # Don't ask for confirmation
        # Hidden imports (ensure all modules are included)
        '--hidden-import', 'colorama',
        '--hidden-import', 'argparse',
        '--hidden-import', 'json',
        '--hidden-import', 'datetime',
        '--hidden-import', 'pathlib',
        # Add data files (if needed)
        # '--add-data', 'README.md;.',
        'main.py'
    ]
    
    try:
        result = subprocess.run(command, check=True, capture_output=False)
        print()
        print("✅ Build successful!")
        print(f"📦 Executable location: dist\\PacketSniffer.exe")
        print()
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        return False

def create_portable_package():
    """Create a portable package ready for USB deployment"""
    print("📁 Creating portable package...")
    
    # Create portable folder
    portable_dir = Path('portable')
    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    portable_dir.mkdir()
    
    # Copy executable
    exe_source = Path('dist/PacketSniffer.exe')
    if exe_source.exists():
        shutil.copy(exe_source, portable_dir / 'PacketSniffer.exe')
        print(f"   ✓ Copied executable")
    
    # Copy README
    readme_source = Path('README.md')
    if readme_source.exists():
        shutil.copy(readme_source, portable_dir / 'README.md')
        print(f"   ✓ Copied README.md")
    
    # Create captures folder
    captures_dir = portable_dir / 'captures'
    captures_dir.mkdir()
    print(f"   ✓ Created captures/ folder")
    
    # Create usage instructions
    usage_text = """PACKET SNIFFER - PORTABLE VERSION
=================================

REQUIREMENTS:
- Windows with Administrator privileges
- No Python installation required!

QUICK START:
1. Right-click on PacketSniffer.exe
2. Select "Run as administrator"
3. Follow the prompts

EXAMPLES:
- Capture 10 packets (default):
  PacketSniffer.exe

- Capture 50 packets with JSON export:
  PacketSniffer.exe -c 50 --export-json

- Capture TCP traffic on port 443:
  PacketSniffer.exe -p tcp --port 443 -c 100

- Endless mode (Ctrl+C to stop):
  PacketSniffer.exe -c 0

For full documentation, see README.md

TROUBLESHOOTING:
- If you get "Permission denied", run as administrator
- If antivirus blocks it, add an exception
- Captured data is saved in captures/ folder

Version: Portable Standalone Edition
"""
    
    usage_file = portable_dir / 'USAGE.txt'
    usage_file.write_text(usage_text, encoding='utf-8')
    print(f"   ✓ Created USAGE.txt")
    
    # Create run script (with admin elevation)
    run_script = """@echo off
echo ========================================
echo  PACKET SNIFFER - Portable Edition
echo ========================================
echo.
echo This tool requires Administrator privileges.
echo.
pause
echo.
echo Starting PacketSniffer...
echo.
PacketSniffer.exe
pause
"""
    
    run_bat = portable_dir / 'Run_PacketSniffer.bat'
    run_bat.write_text(run_script, encoding='utf-8')
    print(f"   ✓ Created Run_PacketSniffer.bat")
    
    print()
    print(f"✅ Portable package created: {portable_dir.absolute()}")
    print()
    print("📦 Package contents:")
    print("   - PacketSniffer.exe      (Standalone executable)")
    print("   - Run_PacketSniffer.bat  (Easy launcher)")
    print("   - README.md              (Full documentation)")
    print("   - USAGE.txt              (Quick reference)")
    print("   - captures/              (Export folder)")
    print()
    print("💾 Ready for USB deployment!")
    print()

def main():
    """Main build process"""
    print()
    print("=" * 50)
    print("  PACKET SNIFFER - PORTABLE BUILD SCRIPT")
    print("=" * 50)
    print()
    
    # Step 1: Clean
    clean_build_folders()
    
    # Step 2: Build
    if not build_executable():
        print("⚠️  Build failed. Exiting...")
        return 1
    
    # Step 3: Create portable package
    create_portable_package()
    
    print("=" * 50)
    print("✅ BUILD COMPLETE!")
    print("=" * 50)
    print()
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Build cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
