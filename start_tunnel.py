#!/usr/bin/env python3
import subprocess
import os
import sys
import time

# ==========================================================
# CONFIGURE YOUR SETTINGS HERE
# ==========================================================
# 1. The name of your SSH key file.
#    Place this file in the SAME FOLDER as this script.
PEM_FILENAME = "lucapns.first.pem"

# 2. Your full portmap.io SSH username (e.g., "lucapns.first").
SSH_USER = "lucapns.first"

# 3. The full portmap.io hostname (e.g., "lucapns-62218.portmap.host").
SSH_HOST = "lucapns-62218.portmap.host"

# 4. The public port assigned to you by portmap.io.
REMOTE_PORT = 62218

# 5. The local port your CodeLogger server will run on.
#    Make sure this matches the --host argument for codelogger.py
LOCAL_PORT = 8001
# ==========================================================


def find_pem_file() -> str:
    """Finds the full path to the .pem file in the script's directory."""
    try:
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        pem_path = os.path.join(script_dir, PEM_FILENAME)

        if not os.path.exists(pem_path):
            print(f"❌ ERROR: Key file not found!")
            print(f"Please make sure '{PEM_FILENAME}' is in the same folder as this script.")
            sys.exit(1) # Exit the script with an error code

        # On macOS/Linux, SSH requires key files to have strict permissions.
        if sys.platform != "win32":
            try:
                os.chmod(pem_path, 0o600)
                print(f"✓ Set permissions for '{PEM_FILENAME}' to 600 (read/write for owner only).")
            except Exception as e:
                print(f"⚠️ Warning: Could not set permissions for key file: {e}")
                print("   If SSH fails, please manually run: chmod 600", pem_path)

        return pem_path
    except Exception as e:
        print(f"❌ An unexpected error occurred while locating the pem file: {e}")
        sys.exit(1)


def start_ssh_tunnel(pem_path: str) -> None:
    """Constructs and runs the SSH command to create the tunnel."""
    public_url = f"http://{SSH_HOST}:{REMOTE_PORT}"
    
    print("="*50)
    print("Starting SSH Remote Tunnel...")
    print(f"  - Public URL: {public_url}")
    print(f"  - Forwarding to: localhost:{LOCAL_PORT}")
    print("="*50)

    # Construct the command as a list of arguments
    command = [
        "ssh",
        # Use the found .pem file
        "-i", pem_path,
        # Automatically accept the host key the first time to avoid prompts
        "-o", "StrictHostKeyChecking=no",
        # Send a "keep-alive" signal every 60 seconds to prevent disconnects
        "-o", "ServerAliveInterval=60",
        # The remote port to listen on, and where to forward it locally
        "-R", f"{REMOTE_PORT}:localhost:{LOCAL_PORT}",
        # The user and host to connect to
        f"{SSH_USER}@{SSH_HOST}",
        # -N: Do not execute a remote command. This is useful for just forwarding ports.
        "-N"
    ]

    try:
        # Use Popen to run the command as a background process
        print("\n🚀 Tunnel command is starting...")
        print("   If it asks for a password, your SSH key may be incorrect.")
        
        process = subprocess.Popen(command)
        
        print("\n✅ Tunnel is now active!")
        print(f"   Access your server at: {public_url}")
        print("\nThis window must remain open to keep the tunnel alive.")
        print("Press Ctrl+C to stop the tunnel.")

        # Keep the script running so the tunnel stays open
        while True:
            time.sleep(1)

    except FileNotFoundError:
        print("❌ ERROR: 'ssh' command not found.")
        print("Please make sure OpenSSH client is installed and in your system's PATH.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nStopping tunnel... ", end="")
        process.terminate() # Stop the SSH process
        print("Done.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An error occurred while running the SSH command: {e}")
        sys.exit(1)


if __name__ == "__main__":
    pem_file_path = find_pem_file()
    start_ssh_tunnel(pem_file_path)
