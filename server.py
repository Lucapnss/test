import argparse
import sys
import os
import subprocess

def main():
    """
    Parses command-line arguments, finds the target script, and executes it,
    passing along any unrecognized arguments.
    """
    # 1. Set up the argument parser to only look for known arguments
    parser = argparse.ArgumentParser(
        description="A server script that launches a Python file with its own arguments.",
        epilog="Example: python server.py --file test.py --host 0.0.0.0 --port 8001"
    )
    
    # 2. Define the '--file' argument for THIS script.
    parser.add_argument(
        '--file',
        type=str,
        required=True,
        help='The path to the Python file to execute.'
    )
    
    # 3. Parse only the known arguments.
    #    'parse_known_args()' returns two values:
    #    - 'known_args': An object with the arguments this parser recognizes (e.g., known_args.file)
    #    - 'remaining_args': A list of all the other arguments that were not recognized.
    known_args, remaining_args = parser.parse_known_args()
    
    file_to_run = known_args.file

    # 4. --- Validation Check ---
    if not os.path.isfile(file_to_run):
        print(f"Error: The file '{file_to_run}' was not found.")
        sys.exit(1)

    # 5. Construct the new command to execute the target script
    #    - sys.executable is the path to the current Python interpreter
    #    - file_to_run is the script we want to run
    #    - remaining_args is the list of arguments for that script (e.g., ['--host', '8001'])
    command = [sys.executable, file_to_run] + remaining_args
    
    print(f"--- [Server] ---")
    print(f"File to execute: {file_to_run}")
    print(f"Arguments being passed: {remaining_args}")
    print(f"Full command: {' '.join(command)}")
    print(f"------------------\n")

    try:
        # 6. Execute the command in a new process
        #    This is the modern and safe way to run another script.
        #    It correctly passes arguments and isolates the process.
        subprocess.run(command, check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"\n--- [Server] ---")
        print(f"Error: The script '{file_to_run}' exited with a non-zero status code: {e.returncode}")
        print(f"------------------")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print(f"\n--- [Server] ---")
        print("Execution interrupted by user.")
        print(f"------------------")
        sys.exit(1)
    except Exception as e:
        print(f"\n--- [Server] ---")
        print(f"An unexpected error occurred: {e}")
        print(f"------------------")
        sys.exit(1)
        
    print(f"\n--- [Server] ---")
    print(f"Finished execution of '{file_to_run}'.")
    print(f"------------------")


if __name__ == "__main__":
    main()