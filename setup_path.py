import os
import sys
import subprocess


def add_to_path_windows(script_dir):
    """Adds the script directory to the user's PATH on Windows."""
    print(f"Attempting to add '{script_dir}' to your PATH.")

    try:
        # Get current user PATH from the registry
        import winreg
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_ALL_ACCESS)
        path_value, _ = winreg.QueryValueEx(reg_key, 'PATH')

        paths = path_value.split(';')
        if script_dir in paths:
            print(f"'{script_dir}' is already in your PATH.")
            return

        # Add the new path
        new_path = f"{path_value};{script_dir}"
        winreg.SetValueEx(reg_key, 'PATH', 0, winreg.REG_EXPAND_SZ, new_path)
        winreg.CloseKey(reg_key)

        # Notify other processes of the change
        import ctypes
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'Environment')

        print("\nSuccess! The script directory has been added to your PATH.")
        print("Please restart your terminal or command prompt for the changes to take effect.")

    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Could not automatically modify the PATH. Please add it manually.")
        print(f"Add the following directory to your User Environment Variables for 'PATH':\n{script_dir}")


def add_to_path_linux(script_dir):
    """Adds the script directory to the user's PATH on Linux/macOS."""
    shell_name = os.path.basename(os.environ.get("SHELL", "bash"))

    if "bash" in shell_name:
        config_file = os.path.expanduser("~/.bashrc")
    elif "zsh" in shell_name:
        config_file = os.path.expanduser("~/.zshrc")
    else:
        print(f"Unsupported shell '{shell_name}'. Please add the path manually.")
        print(f"Add this line to your shell's startup file (e.g., ~/.profile):")
        print(f'\nexport PATH="$PATH:{script_dir}"\n')
        return

    path_line = f'export PATH="$PATH:{script_dir}"'

    try:
        with open(config_file, 'r') as f:
            if path_line in f.read():
                print(f"'{script_dir}' is already in your PATH in {config_file}.")
                return

        with open(config_file, 'a') as f:
            f.write(f"\n# Added by sendstash setup script\n")
            f.write(f"{path_line}\n")

        print(f"\nSuccess! Added the script directory to {config_file}.")
        print("Please run the following command or restart your terminal for the changes to take effect:")
        print(f"source {config_file}")

    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Could not automatically modify the PATH. Please add it manually.")
        print(f"Add this line to your shell's startup file (e.g., {config_file}):")
        print(f'\n{path_line}\n')


def main():
    """Main function to run the setup script."""
    script_dir = os.path.abspath(os.path.dirname(__file__))

    print("--- SendStash PATH Setup ---")

    if sys.platform == "win32":
        add_to_path_windows(script_dir)
    elif sys.platform == "linux" or sys.platform == "darwin":
        add_to_path_linux(script_dir)
    else:
        print(f"Unsupported platform: {sys.platform}")
        print("Please add the script directory to your PATH manually.")
        print(script_dir)

if __name__ == '__main__':
    main()
