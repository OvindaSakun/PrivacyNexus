import os
import shutil
import customtkinter
from py2exe import freeze

# Get CustomTkinter package directory
ctk_dir = os.path.dirname(customtkinter.__file__)

# Build executables
freeze(
    windows=[
        {
            "script": "vmware_os_loader.py",
            "dest_base": "vmware_os_loader"
        },
        {
            "script": "gui_app.py",
            "dest_base": "gui_app"
        }
    ],
    options={
        "py2exe": {
            "bundle_files": 3,
            "compressed": True,
            "packages": ["customtkinter", "Crypto", "PIL", "serial", "psutil"],
            "includes": ["tkinter", "json", "socket", "urllib", "threading"],
            "dist_dir": "dist"
        }
    },
    zipfile=None
)

# Copy CustomTkinter asset folders (themes, fonts, etc.) to all possible runtime lookup locations
dist_dir = os.path.abspath("dist")

targets = [
    os.path.join(dist_dir, "customtkinter"),
    os.path.join(dist_dir, "vmware_os_loader.exe", "customtkinter"),
    os.path.join(dist_dir, "gui_app.exe", "customtkinter"),
]

if os.path.exists(ctk_dir):
    for target in targets:
        try:
            if os.path.exists(target):
                shutil.rmtree(target)
            shutil.copytree(ctk_dir, target)
            print(f"[*] CustomTkinter assets copied to: {target}")
        except Exception as e:
            print(f"[*] Copy notice for {target}: {e}")

print("\n=======================================================")
print("  BUILD COMPLETE! Executables created in 'dist' folder:")
print("  1. dist/vmware_os_loader.exe")
print("  2. dist/gui_app.exe")
print("=======================================================\n")
