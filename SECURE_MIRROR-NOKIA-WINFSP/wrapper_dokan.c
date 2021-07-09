
/////  FILE INCLUDES  /////

#include <Windows.h>
#include "dokan.h"
#include <stdio.h>
#include <stdlib.h>
#include "psapi.h"
#include <malloc.h>

//includes propios
#include "config.h"
#include "context.h"
#include "wrapper_dokan.h"
#include "main.h"
#include "logic.h"




/////  DEFINITIONS  /////

// #define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

#define MirrorCheckFlag(val, flag) if (val & flag) { DbgPrint(L"\t" L#flag L"\n"); };

// This macro uses a parameter name from mirror functions (only works inside them)
#define THREAD_INDEX DokanFileInfo->DokanOptions->thread_index




/////  GLOBAL VARIABLES  /////

BOOL g_UseStdErr;
BOOL g_DebugMode;
BOOL g_CaseSensitive;
BOOL g_HasSeSecurityPrivilege;
BOOL g_ImpersonateCallerUser;

BOOL g_SecureLogs;	//Variable para logs de SecureWorld

static WCHAR RootDirectory[NUM_LETTERS][DOKAN_MAX_PATH] = { L"C:" };
static WCHAR MountPoint[NUM_LETTERS][DOKAN_MAX_PATH] = { L"M:\\" };
static WCHAR UNCName[NUM_LETTERS][DOKAN_MAX_PATH] = { L"" };
static WCHAR* volume_names[NUM_LETTERS] = { NULL };
//static struct VolumeInfo* volume_info[NUM_LETTERS] = { NULL };
// TO DO protections here instead of Cipher or others
static struct Protection* protections[NUM_LETTERS] = { NULL };




/////  FUNCTION PROTOTYPES  /////

WCHAR* getAppPathDokan(PDOKAN_FILE_INFO dokan_file_info);

static void DbgPrint(LPCWSTR format, ...);
static void GetFilePath(PWCHAR filePath, ULONG numberOfElements, LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo);
static BOOL AddSeSecurityNamePrivilege();
static NTSTATUS DOKAN_CALLBACK MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo);
static void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation( LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorFindFiles(LPCWSTR FileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorMoveFile(LPCWSTR FileName, LPCWSTR NewFileName, BOOL ReplaceIfExisting, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorLockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile(LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize(LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes(LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorSetFileTime(LPCWSTR FileName, CONST FILETIME * CreationTime, CONST FILETIME * LastAccessTime, CONST FILETIME * LastWriteTime, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorUnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity(LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength, PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity(LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation(LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber, LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags, LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes, PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo);
#pragma region NtQueryInformationFile() --> does not include function definition
/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for MirrorFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
#pragma warning(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */
#pragma endregion
NTSTATUS DOKAN_CALLBACK MirrorFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData, PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorMounted(PDOKAN_FILE_INFO DokanFileInfo);
static NTSTATUS DOKAN_CALLBACK MirrorUnmounted(PDOKAN_FILE_INFO DokanFileInfo);




/////  FUNCTION DEFINITIONS  /////

int dokanMapAndLaunch(int index, WCHAR* path, WCHAR letter, WCHAR* volume_name, struct Protection* protection) {
	DOKAN_OPTIONS dokan_options;
	DOKAN_OPERATIONS dokan_operations;

	PRINT("DokanMapAndLaunch parameters:    index=%2d     letter=%wc     path='%ws'\n", index, letter, path);

	// Fill dokan options
	ZeroMemory(&dokan_options, sizeof(DOKAN_OPTIONS));
	dokan_options.Version = DOKAN_VERSION;
	dokan_options.ThreadCount = 0; // use default
	dokan_options.thread_index = index;
	wcscpy_s(RootDirectory[index], sizeof(RootDirectory[index]) / sizeof(WCHAR), path);

	WCHAR letter_and_null[2] = { L'\0', L'\0' };
	letter_and_null[0] = letter;
	wcscpy_s(MountPoint[index], 2, letter_and_null);
	dokan_options.MountPoint = MountPoint[index];

	protections[index] = protection;
	volume_names[index] = volume_name;

	// Fill dokan operations
	ZeroMemory(&dokan_operations, sizeof(DOKAN_OPERATIONS));
	dokan_operations.ZwCreateFile = MirrorCreateFile;                  // Will be modified
	dokan_operations.Cleanup = MirrorCleanup;
	dokan_operations.CloseFile = MirrorCloseFile;
	dokan_operations.ReadFile = MirrorReadFile;                        // Will be modified
	dokan_operations.WriteFile = MirrorWriteFile;                      // Will be modified
	dokan_operations.FlushFileBuffers = MirrorFlushFileBuffers;
	dokan_operations.GetFileInformation = MirrorGetFileInformation;    // Will be modified parental control??
	dokan_operations.FindFiles = MirrorFindFiles;
	dokan_operations.FindFilesWithPattern = NULL;
	dokan_operations.SetFileAttributes = MirrorSetFileAttributes;
	dokan_operations.SetFileTime = MirrorSetFileTime;
	dokan_operations.DeleteFile = MirrorDeleteFile;
	dokan_operations.DeleteDirectory = MirrorDeleteDirectory;
	dokan_operations.MoveFile = MirrorMoveFile;
	dokan_operations.SetEndOfFile = MirrorSetEndOfFile;
	dokan_operations.SetAllocationSize = MirrorSetAllocationSize;
	dokan_operations.LockFile = MirrorLockFile;
	dokan_operations.UnlockFile = MirrorUnlockFile;
	dokan_operations.GetFileSecurity = MirrorGetFileSecurity;
	dokan_operations.SetFileSecurity = MirrorSetFileSecurity;
	dokan_operations.GetDiskFreeSpace = MirrorDokanGetDiskFreeSpace;
	dokan_operations.GetVolumeInformation = MirrorGetVolumeInformation;
	dokan_operations.Unmounted = MirrorUnmounted;
	dokan_operations.FindStreams = MirrorFindStreams;
	dokan_operations.Mounted = MirrorMounted;

	// Launch dokan (never ending function)
	int status;
	status = DokanMain(&dokan_options, &dokan_operations);

	switch (status) {
		case DOKAN_SUCCESS:
			fprintf(stderr, "Success\n");
			break;
		case DOKAN_ERROR:
			fprintf(stderr, "Error\n");
			break;
		case DOKAN_DRIVE_LETTER_ERROR:
			fprintf(stderr, "Bad Drive letter\n");
			break;
		case DOKAN_DRIVER_INSTALL_ERROR:
			fprintf(stderr, "Can't install driver\n");
			break;
		case DOKAN_START_ERROR:
			fprintf(stderr, "Driver something wrong\n");
			break;
		case DOKAN_MOUNT_ERROR:
			fprintf(stderr, "Can't assign a drive letter\n");
			break;
		case DOKAN_MOUNT_POINT_ERROR:
			fprintf(stderr, "Mount point error\n");
			break;
		case DOKAN_VERSION_ERROR:
			fprintf(stderr, "Version error\n");
			break;
		default:
			fprintf(stderr, "Unknown error: %d\n", status);
			break;
	}
	return EXIT_SUCCESS;
}

/**
* Returns the full path of the application performing an file operation (open, read, write, etc.) in a Dokan filesystem
* Note the returned full path is in Device form. Example: "\\Device\\Harddisk0\\Partition1\\Windows\\System32\\Ctype.nls"
* Memory for the path is allocated inside, remember to free after use.
*
* @param PDOKAN_FILE_INFO dokan_file_info:
*		The dokan information of the file filesystem operation.
*
* @return WCHAR*:
*		The full path of the application performing the file operation.
**/
WCHAR* getAppPathDokan(PDOKAN_FILE_INFO dokan_file_info) {
	HANDLE process_handle;
	WCHAR* process_full_path = NULL;
	DWORD process_full_path_length = 0;

	process_full_path_length = MAX_PATH;
	process_full_path = malloc(process_full_path_length * sizeof(WCHAR));
	if (process_full_path != NULL) {
		process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dokan_file_info->ProcessId);

		if (GetProcessImageFileNameW(process_handle, process_full_path, process_full_path_length) > 0) {
			CloseHandle(process_handle);
			return process_full_path;
		}
		CloseHandle(process_handle);
		free(process_full_path);
	}

	return NULL;
}


static void DbgPrint(LPCWSTR format, ...) {
	if (g_DebugMode) {
		const WCHAR* outputString;
		WCHAR* buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = _malloca(length * sizeof(WCHAR));
		if (buffer) {
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		} else {
			outputString = format;
		}
		if (g_UseStdErr)
			fputws(outputString, stderr);
		else
			OutputDebugStringW(outputString);
		if (buffer)
			_freea(buffer);
		va_end(argp);
		if (g_UseStdErr)
			fflush(stderr);
	}
}


static void GetFilePath(PWCHAR filePath, ULONG numberOfElements, LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
	wcsncpy_s(filePath, numberOfElements, RootDirectory[THREAD_INDEX], wcslen(RootDirectory[THREAD_INDEX]));
	size_t unclen = wcslen(UNCName[THREAD_INDEX]);
	if (unclen > 0 && _wcsnicmp(FileName, UNCName[THREAD_INDEX], unclen) == 0) {
		if (_wcsnicmp(FileName + unclen, L".", 1) != 0) {
			wcsncat_s(filePath, numberOfElements, FileName + unclen, wcslen(FileName) - unclen);
		}
	} else {
		wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
	}
}


static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {
	HANDLE handle;
	UCHAR buffer[1024];
	DWORD returnLength;
	WCHAR accountName[256];
	WCHAR domainName[256];
	DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
	DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
	PTOKEN_USER tokenUser;
	SID_NAME_USE snu;

	if (!g_DebugMode)
		return;

	handle = DokanOpenRequestorToken(DokanFileInfo);
	if (handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"  DokanOpenRequestorToken failed\n");
		return;
	}

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
		&returnLength)) {
		DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
		CloseHandle(handle);
		return;
	}

	CloseHandle(handle);

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
		domainName, &domainLength, &snu)) {
		DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
		return;
	}

	DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}


static BOOL AddSeSecurityNamePrivilege() {
	HANDLE token = 0;
	DbgPrint(L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
	DWORD err;
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to lookup privilege value. error = %u\n", err);
			return FALSE;
		}
	}

	LUID_AND_ATTRIBUTES attr;
	attr.Attributes = SE_PRIVILEGE_ENABLED;
	attr.Luid = luid;

	TOKEN_PRIVILEGES priv;
	priv.PrivilegeCount = 1;
	priv.Privileges[0] = attr;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);
			return FALSE;
		}
	}

	TOKEN_PRIVILEGES oldPriv;
	DWORD retSize;
	AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
		&retSize);
	err = GetLastError();
	if (err != ERROR_SUCCESS) {
		DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
		CloseHandle(token);
		return FALSE;
	}

	BOOL privAlreadyPresent = FALSE;
	for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
		if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
			oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
			privAlreadyPresent = TRUE;
			break;
		}
	}
	DbgPrint(privAlreadyPresent ? L"  success: privilege already present\n" : L"  success: privilege added\n");
	if (token)
		CloseHandle(token);
	return TRUE;
}


static NTSTATUS DOKAN_CALLBACK
MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR file_path[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD fileAttr;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	DWORD error = 0;
	SECURITY_ATTRIBUTES securityAttrib;
	ACCESS_MASK genericDesiredAccess;
	// userTokenHandle is for Impersonate Caller User Option
	HANDLE userTokenHandle = INVALID_HANDLE_VALUE;
	securityAttrib.nLength = sizeof(securityAttrib);
	securityAttrib.lpSecurityDescriptor = SecurityContext->AccessState.SecurityDescriptor;
	securityAttrib.bInheritHandle = FALSE;

	DokanMapKernelToUserCreateFileFlags(
		DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
		&genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

	GetFilePath(file_path, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"CreateFile : %s\n", file_path);
	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: CreateFile\n", filePath);
	//==========================================================

	WCHAR* full_app_path;
	full_app_path = getAppPathDokan(DokanFileInfo);


	if (preCreateLogic(file_path, full_app_path)) {
		return STATUS_IO_PRIVILEGE_FAILED;						// TO DO complete
	}



	PrintUserName(DokanFileInfo);

	/*
	if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
			ShareMode = FILE_SHARE_WRITE;
	else if (ShareMode == 0)
			ShareMode = FILE_SHARE_READ;
	*/

	DbgPrint(L"\tShareMode = 0x%x\n", ShareAccess);

	MirrorCheckFlag(ShareAccess, FILE_SHARE_READ);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_WRITE);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_DELETE);

	DbgPrint(L"\tDesiredAccess = 0x%x\n", DesiredAccess);

	MirrorCheckFlag(DesiredAccess, GENERIC_READ);
	MirrorCheckFlag(DesiredAccess, GENERIC_WRITE);
	MirrorCheckFlag(DesiredAccess, GENERIC_EXECUTE);

	MirrorCheckFlag(DesiredAccess, DELETE);
	MirrorCheckFlag(DesiredAccess, FILE_READ_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_READ_EA);
	MirrorCheckFlag(DesiredAccess, READ_CONTROL);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_EA);
	MirrorCheckFlag(DesiredAccess, FILE_APPEND_DATA);
	MirrorCheckFlag(DesiredAccess, WRITE_DAC);
	MirrorCheckFlag(DesiredAccess, WRITE_OWNER);
	MirrorCheckFlag(DesiredAccess, SYNCHRONIZE);
	MirrorCheckFlag(DesiredAccess, FILE_EXECUTE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

	// When filePath is a directory, needs to change the flag so that the file can be opened.
	fileAttr = GetFileAttributes(file_path);

	if (fileAttr != INVALID_FILE_ATTRIBUTES
		&& fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
		if (!(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
			DokanFileInfo->IsDirectory = TRUE;
			// Needed by FindFirstFile to list files in it
			// TODO: use ReOpenFile in MirrorFindFiles to set share read temporary
			ShareAccess |= FILE_SHARE_READ;
		} else { // FILE_NON_DIRECTORY_FILE - Cannot open a dir as a file
			DbgPrint(L"\tCannot open a dir as a file\n");
			return STATUS_FILE_IS_A_DIRECTORY;
		}
	}

	DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_COMPRESSED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DEVICE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_INTEGRITY_STREAM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NO_SCRUB_DATA);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SPARSE_FILE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_VIRTUAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

	if (g_CaseSensitive)
		fileAttributesAndFlags |= FILE_FLAG_POSIX_SEMANTICS;

	if (creationDisposition == CREATE_NEW) {
		DbgPrint(L"\tCREATE_NEW\n");
	} else if (creationDisposition == OPEN_ALWAYS) {
		DbgPrint(L"\tOPEN_ALWAYS\n");
	} else if (creationDisposition == CREATE_ALWAYS) {
		DbgPrint(L"\tCREATE_ALWAYS\n");
	} else if (creationDisposition == OPEN_EXISTING) {
		DbgPrint(L"\tOPEN_EXISTING\n");
	} else if (creationDisposition == TRUNCATE_EXISTING) {
		DbgPrint(L"\tTRUNCATE_EXISTING\n");
	} else {
		DbgPrint(L"\tUNKNOWN creationDisposition!\n");
	}

	if (g_ImpersonateCallerUser) {
		userTokenHandle = DokanOpenRequestorToken(DokanFileInfo);

		if (userTokenHandle == INVALID_HANDLE_VALUE) {
			DbgPrint(L"  DokanOpenRequestorToken failed\n");
			// Should we return some error?
		}
	}

	if (DokanFileInfo->IsDirectory) {
		// It is a create directory request

		if (creationDisposition == CREATE_NEW || creationDisposition == OPEN_ALWAYS) {

			if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
				// if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
				if (!ImpersonateLoggedOnUser(userTokenHandle)) {
					// handle the error if failed to impersonate
					DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
				}
			}

			//We create folder
			if (!CreateDirectory(file_path, &securityAttrib)) {
				error = GetLastError();
				// Fail to create folder for OPEN_ALWAYS is not an error
				if (error != ERROR_ALREADY_EXISTS || creationDisposition == CREATE_NEW) {
					DbgPrint(L"\terror code = %d\n\n", error);
					status = DokanNtStatusFromWin32(error);
				}
			}

			if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
				// Clean Up operation for impersonate
				DWORD lastError = GetLastError();
				if (status != STATUS_SUCCESS) //Keep the handle open for CreateFile
					CloseHandle(userTokenHandle);
				RevertToSelf();
				SetLastError(lastError);
			}
		}

		if (status == STATUS_SUCCESS) {

			//Check first if we're trying to open a file as a directory.
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				!(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
				(CreateOptions & FILE_DIRECTORY_FILE)) {
				return STATUS_NOT_A_DIRECTORY;
			}

			if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
				// if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
				if (!ImpersonateLoggedOnUser(userTokenHandle)) {
					// handle the error if failed to impersonate
					DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
				}
			}

			// FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
			handle = CreateFile(file_path, genericDesiredAccess, ShareAccess, &securityAttrib, OPEN_EXISTING, fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

			if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
				// Clean Up operation for impersonate
				DWORD lastError = GetLastError();
				CloseHandle(userTokenHandle);
				RevertToSelf();
				SetLastError(lastError);
			}

			if (handle == INVALID_HANDLE_VALUE) {
				error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);

				status = DokanNtStatusFromWin32(error);
			} else {
				DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context

				// Open succeed but we need to inform the driver
				// that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
				if (creationDisposition == OPEN_ALWAYS &&
					fileAttr != INVALID_FILE_ATTRIBUTES)
					return STATUS_OBJECT_NAME_COLLISION;
			}
		}
	} else {
		// It is a create file request

		// Cannot overwrite a hidden or system file if flag not set
		if (fileAttr != INVALID_FILE_ATTRIBUTES &&
			((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
				(fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
				(!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
					(fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
			(creationDisposition == TRUNCATE_EXISTING ||
				creationDisposition == CREATE_ALWAYS))
			return STATUS_ACCESS_DENIED;

		// Cannot delete a read only file
		if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
			(fileAttr & FILE_ATTRIBUTE_READONLY) ||
			(fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
			(fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE))
			return STATUS_CANNOT_DELETE;

		// Truncate should always be used with write access
		if (creationDisposition == TRUNCATE_EXISTING)
			genericDesiredAccess |= GENERIC_WRITE;

		if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
			// if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
			if (!ImpersonateLoggedOnUser(userTokenHandle)) {
				// handle the error if failed to impersonate
				DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
			}
		}

		handle = CreateFile(
			file_path,
			genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			ShareAccess,
			&securityAttrib, // security attribute
			creationDisposition,
			fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			NULL);                  // template file handle

		if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
			// Clean Up operation for impersonate
			DWORD lastError = GetLastError();
			CloseHandle(userTokenHandle);
			RevertToSelf();
			SetLastError(lastError);
		}

		if (handle == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			DbgPrint(L"\terror code = %d\n\n", error);

			status = DokanNtStatusFromWin32(error);

		} else {
			//Need to update FileAttributes with previous when Overwrite file
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				creationDisposition == TRUNCATE_EXISTING) {
				SetFileAttributes(file_path, fileAttributesAndFlags | fileAttr);
			}

			DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context

			if (creationDisposition == OPEN_ALWAYS ||
				creationDisposition == CREATE_ALWAYS) {
				error = GetLastError();
				if (error == ERROR_ALREADY_EXISTS) {
					DbgPrint(L"\tOpen an already existing file\n");
					// Open succeed but we need to inform the driver
					// that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
					status = STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}

	DbgPrint(L"\n");
	return status;
}

#pragma warning(push)
#pragma warning(disable : 4305)

static void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);
	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: CloseFile\n", filePath);
	//==========================================================
	if (DokanFileInfo->Context) {
		DbgPrint(L"CloseFile: %s\n", filePath);
		DbgPrint(L"\terror : not cleanuped file\n\n");
		CloseHandle((HANDLE)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	} else {
		DbgPrint(L"Close: %s\n\n", filePath);
	}
}

static void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: CleanUp\n", filePath);
	//==========================================================

	if (DokanFileInfo->Context) {
		DbgPrint(L"Cleanup: %s\n\n", filePath);
		CloseHandle((HANDLE)(DokanFileInfo->Context));
		DokanFileInfo->Context = 0;
	} else {
		DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", filePath);
	}

	if (DokanFileInfo->DeleteOnClose) {
		// Should already be deleted by CloseHandle
		// if open with FILE_FLAG_DELETE_ON_CLOSE
		DbgPrint(L"\tDeleteOnClose\n");
		if (DokanFileInfo->IsDirectory) {
			DbgPrint(L"  DeleteDirectory ");
			if (!RemoveDirectory(filePath)) {
				DbgPrint(L"error code = %d\n\n", GetLastError());
			} else {
				DbgPrint(L"success\n\n");
			}
		} else {
			DbgPrint(L"  DeleteFile ");
			if (DeleteFile(filePath) == 0) {
				DbgPrint(L" error code = %d\n\n", GetLastError());
			} else {
				DbgPrint(L"success\n\n");
			}
		}
	}
}

static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR file_path[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	//ULONG offset = (ULONG)Offset;
	BOOL opened = FALSE;
	GetFilePath(file_path, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	// Create auxiliar parameters for internal modification of the operation (mark and possible block cipher)
	LPVOID aux_buffer = NULL;
	DWORD aux_buffer_length = 0;
	LPDWORD aux_read_length = NULL;
	LONGLONG aux_offset = 0;

	DWORD error_code = 0;

	WCHAR* full_app_path = NULL;
	enum Operation op1;
	enum Operation op2;
	enum Operation op_final = NOTHING;

	full_app_path = getAppPathDokan(DokanFileInfo);
	PRINT("Op: MIRROR READ FILE,   APP_Path: %ws,   FILE_path: %ws\n", full_app_path, file_path);

	op1 = getTableOperation(ON_READ, &full_app_path, MountPoint[THREAD_INDEX][0]);
	op2 = getOpSyncFolder(ON_READ, file_path);

	op_final = operationAddition(op1, op2);
	PRINT("Obtained operations: op1=%d, op2=%d, op_final=%d\n", op1, op2, op_final);

	// Get file size
	uint64_t file_size;
	error_code = getFileSize(&file_size, handle, file_path);
	if (error_code != 0) {
		PRINT("ERROR getting file size\n");
		goto READ_CLEANUP;			// Handle case where file size cannot be obtained. Abort operation??
	}

	// Initialize new read variables with updated values adjusted for the mark and possible block cipher
	error_code = preReadLogic(
		file_size, op_final,
		&Buffer, &BufferLength, &ReadLength, &Offset,
		&aux_buffer, &aux_buffer_length, &aux_read_length, &aux_offset
	);
	if (error_code != 0) {
		PRINT("ERROR in preReadLogic\n");
		goto READ_CLEANUP;
	}

	DbgPrint(L"ReadFile : %s\n", file_path);
	PRINT("Vamos al handle\n");

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		PRINT("wrapper_dokan: invalid handle\n");
		handle = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			error_code = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error_code);
			PRINT("wrapper_dokan: cannot create handle\n");
			goto READ_CLEANUP;
		}
		opened = TRUE;
	}

	PRINT("Vamos al distance to move\n");

	LARGE_INTEGER distanceToMove;
	distanceToMove.QuadPart = aux_offset;
	if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		DbgPrint(L"\tseek error, offset = %lld\n\n", aux_offset);
		goto READ_CLEANUP;
	}

	PRINT("Vamos al read\n");

	// Read
	if (!ReadFile(
		handle,
		aux_buffer,
		aux_buffer_length,
		aux_read_length,
		NULL)
		) {
		error_code = GetLastError();
		DbgPrint(L"\tread error = %u, buffer length = %u, read length = %u\n\n", error_code, aux_buffer_length, *aux_read_length);
		goto READ_CLEANUP;
	}


	// Initialize new read variables with updated values adjusted for the mark and possible block cipher
	error_code = postReadLogic(
		file_size, op_final, protections[THREAD_INDEX], handle,
		&Buffer, &BufferLength, &ReadLength, &Offset,
		&aux_buffer, &aux_buffer_length, &aux_read_length, &aux_offset
	);
	if (error_code != 0) {
		PRINT("ERROR in postReadLogic.\n");
		goto READ_CLEANUP;
	}

	DbgPrint(L"\tByte to read: %d, Byte read %d, offset %lld\n\n", BufferLength, *ReadLength, Offset);

	READ_CLEANUP:
	if (opened) {
		PRINT("close handle\n");
		CloseHandle(handle);
	}
	if (aux_buffer != Buffer && aux_buffer != NULL) {
		PRINT("free(aux_buffer)\n");
		free(aux_buffer);
	}
	if (aux_read_length != ReadLength && aux_read_length != NULL) {
		PRINT("free(aux_read_length)\n");
		free(aux_read_length);
	}
	if (full_app_path != NULL) {
		PRINT("free(full app path)\n");
		free(full_app_path);
	}
	if (error_code) {
		PRINT("Devuelvo error (%d)\n", error_code);
		return DokanNtStatusFromWin32(error_code);
	}

	//PRINT("Hemos leido 3: %.520s END\n", (char*)Buffer);
	//PRINT("Hemos leido 4: %.50s END\n", &(((char*)Buffer)[513]));
	PRINT("Final\n");

	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer,
	DWORD NumberOfBytesToWrite,
	LPDWORD NumberOfBytesWritten,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR file_path[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	GetFilePath(file_path, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	// Create aux params
	LPVOID aux_buffer = NULL;
	DWORD aux_bytes_to_write = 0;
	LPDWORD aux_bytes_written = NULL;
	LONGLONG aux_offset = 0;

	DWORD error_code = 0;

	WCHAR* full_app_path = NULL;
	enum Operation op1;
	enum Operation op2;
	enum Operation op_final = NOTHING;

	full_app_path = getAppPathDokan(DokanFileInfo);
	printf("Op: MIRROR WRITE FILE,   APP_Path: %ws,   FILE_path: %ws\n", full_app_path, file_path);

	op1 = getTableOperation(ON_WRITE, &full_app_path, MountPoint[THREAD_INDEX][0]); // Better directly create global variable with pointer to table in this mounted disk
	op2 = getOpSyncFolder(ON_WRITE, file_path);

	op_final = operationAddition(op1, op2);
	PRINT("Obtained operations: op1=%d, op2=%d, op_final=%d\n", op1, op2, op_final);


	// Get file size
	uint64_t file_size;
	error_code = getFileSize(&file_size, handle, file_path);
	if (error_code != 0) {
		PRINT("ERROR getting file size\n");
		goto WRITE_CLEANUP;			// Handle case where file size cannot be obtained. Abort operation??
	}

	error_code = preWriteLogic(
		&file_size, op_final, file_path, protections[THREAD_INDEX], handle, DokanFileInfo->WriteToEndOfFile,
		&Buffer, &NumberOfBytesToWrite, &NumberOfBytesWritten, &Offset,
		&aux_buffer, &aux_bytes_to_write, &aux_bytes_written, &aux_offset
	);
	if (error_code != 0) {
		PRINT("ERROR in preWriteLogic. error_code = %d\n", error_code);
		goto WRITE_CLEANUP;
	}

	DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", file_path, Offset, NumberOfBytesToWrite);

	// Reopen file handle if needed
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(file_path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			error_code = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error_code);
			goto WRITE_CLEANUP;
		}
		opened = TRUE;
	}

	UINT64 fileSize = 0;
	DWORD fileSizeLow = 0;
	DWORD fileSizeHigh = 0;
	fileSizeLow = GetFileSize(handle, &fileSizeHigh);
	if (fileSizeLow == INVALID_FILE_SIZE) {
		error_code = GetLastError();
		DbgPrint(L"\tcan not get a file size error = %d\n", error_code);
		/*if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);*/
		goto WRITE_CLEANUP;
	}

	fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

	LARGE_INTEGER distanceToMove;
	if (DokanFileInfo->WriteToEndOfFile) {
		LARGE_INTEGER z;
		z.QuadPart = 0;
		if (!SetFilePointerEx(handle, z, NULL, FILE_END)) {
			DWORD error_code = GetLastError();
			DbgPrint(L"\tseek error, offset = EOF, error = %d\n", error_code);
			/*if (opened)
				CloseHandle(handle);
			return DokanNtStatusFromWin32(error);*/
			goto WRITE_CLEANUP;
		}
	} else {
		// Paging IO cannot write after allocate file size.
		if (DokanFileInfo->PagingIo) {
			if ((UINT64)Offset >= fileSize) {
				*NumberOfBytesWritten = 0;
				/*if (opened)
					CloseHandle(handle);
				return STATUS_SUCCESS;*/
				goto WRITE_CLEANUP;
			}

			if (((UINT64)Offset + NumberOfBytesToWrite) > fileSize) {
				UINT64 bytes = fileSize - Offset;
				if (bytes >> 32) {
					NumberOfBytesToWrite = (DWORD)(bytes & 0xFFFFFFFFUL);
				} else {
					NumberOfBytesToWrite = (DWORD)bytes;
				}
			}
		}

		if ((UINT64)Offset > fileSize) {
			// In the mirror sample helperZeroFileData is not necessary. NTFS will zero a hole.
			// But if user's file system is different from NTFS (or other Windows's file systems)
			// then  users will have to zero the hole themselves.
		}

		distanceToMove.QuadPart = Offset;
		if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
			DWORD error_code = GetLastError();
			DbgPrint(L"\tseek error, offset = %I64d, error = %d\n", Offset, error_code);
			/*if (opened)
				CloseHandle(handle);
			return DokanNtStatusFromWin32(error);*/
			goto WRITE_CLEANUP;
		}
	}

	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: WriteFile\n", file_path);
	//==========================================================

	if (!WriteFile(
			handle,
			aux_buffer,
			aux_bytes_to_write,
			aux_bytes_written,
			NULL)
		) {
		DWORD error_code = GetLastError();
		DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n", error_code, NumberOfBytesToWrite, *NumberOfBytesWritten);
		/*if (opened)
			CloseHandle(handle);
		return DokanNtStatusFromWin32(error);*/
		goto WRITE_CLEANUP;

	} else {
		DbgPrint(L"\twrite %d, offset %I64d\n\n", *NumberOfBytesWritten, Offset);
	}

	error_code = postWriteLogic(
		&file_size, op_final, file_path, protections[THREAD_INDEX], handle, DokanFileInfo->WriteToEndOfFile,
		&Buffer, &NumberOfBytesToWrite, &NumberOfBytesWritten, &Offset,
		&aux_buffer, &aux_bytes_to_write, &aux_bytes_written, &aux_offset
	);
	if (error_code != 0) {
		PRINT("ERROR in postWriteLogic. error_code = %d\n", error_code);
		goto WRITE_CLEANUP;
	}


	WRITE_CLEANUP:
	if (opened) {
		CloseHandle(handle);
	}
	if (aux_buffer != Buffer && aux_buffer != NULL) {
		free(aux_buffer);
	}
	/*if (aux_bytes_written != NumberOfBytesWritten && aux_bytes_written != NULL) {
		free(aux_bytes_written);
	}*/
	if (full_app_path != NULL) {
		free(full_app_path);
	}
	if (error_code) {
		return DokanNtStatusFromWin32(error_code);
	}


	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: FlushFileBuffers\n", file_path);
	//==========================================================

	DbgPrint(L"FlushFileBuffers : %s\n", filePath);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_SUCCESS;
	}

	if (FlushFileBuffers(handle)) {
		return STATUS_SUCCESS;
	} else {
		DWORD error = GetLastError();
		DbgPrint(L"\tflush error code = %d\n", error);
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation(
	LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: GetFileInformation\n", file_path);
	//==========================================================

	DbgPrint(L"GetFileInfo : %s\n", filePath);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error);
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	if (!GetFileInformationByHandle(handle, HandleFileInformation)) {
		DbgPrint(L"\terror code = %d\n", GetLastError());

		// FileName is a root directory
		// in this case, FindFirstFile can't get directory information
		if (wcslen(FileName) == 1) {
			DbgPrint(L"  root dir\n");
			HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath);

		} else {
			WIN32_FIND_DATAW find;
			ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
			HANDLE findHandle = FindFirstFile(filePath, &find);
			if (findHandle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				DbgPrint(L"\tFindFirstFile error code = %d\n\n", error);
				if (opened)
					CloseHandle(handle);
				return DokanNtStatusFromWin32(error);
			}
			HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
			HandleFileInformation->ftCreationTime = find.ftCreationTime;
			HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
			HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;
			HandleFileInformation->nFileSizeHigh = find.nFileSizeHigh;
			HandleFileInformation->nFileSizeLow = find.nFileSizeLow;
			DbgPrint(L"\tFindFiles OK, file size = %d\n", find.nFileSizeLow);
			FindClose(findHandle);
		}
	} else {
		DbgPrint(L"\tGetFileInformationByHandle success, file size = %d\n", HandleFileInformation->nFileSizeLow);
	}

	DbgPrint(L"FILE ATTRIBUTE  = %d\n", HandleFileInformation->dwFileAttributes);

	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorFindFiles(LPCWSTR FileName,
	PFillFindData FillFindData, // function pointer
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	size_t fileLen;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	DWORD error;
	int count = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);
	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: FindFiles\n", file_path);
	//==========================================================

	DbgPrint(L"FindFiles : %s\n", filePath);

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	if (fileLen + 1 >= DOKAN_MAX_PATH)
		return STATUS_BUFFER_OVERFLOW;
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	// Root folder does not have . and .. folder - we remove them
	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
	do {
		if (!rootFolder || (wcscmp(findData.cFileName, L".") != 0 &&
			wcscmp(findData.cFileName, L"..") != 0))
			FillFindData(&findData, DokanFileInfo);
		count++;
	} while (FindNextFile(hFind, &findData) != 0);

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		DbgPrint(L"\tFindNextFile error. Error is %u\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\tFindFiles return %d entries in %s\n\n", count, filePath);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);
	DbgPrint(L"DeleteFile %s - %d\n", filePath, DokanFileInfo->DeleteOnClose);

	DWORD dwAttrib = GetFileAttributes(filePath);

	if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		return STATUS_ACCESS_DENIED;

	if (handle && handle != INVALID_HANDLE_VALUE) {
		FILE_DISPOSITION_INFO fdi;
		fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
		if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
			sizeof(FILE_DISPOSITION_INFO)))
			return DokanNtStatusFromWin32(GetLastError());
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	//HANDLE handle = (HANDLE)DokanFileInfo->Context;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	size_t fileLen;

	ZeroMemory(filePath, sizeof(filePath));
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"DeleteDirectory %s - %d\n", filePath,
		DokanFileInfo->DeleteOnClose);

	if (!DokanFileInfo->DeleteOnClose)
		// Dokan notify that the file is requested not to be deleted.
		return STATUS_SUCCESS;

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	if (fileLen + 1 >= DOKAN_MAX_PATH)
		return STATUS_BUFFER_OVERFLOW;
	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	do {
		if (wcscmp(findData.cFileName, L"..") != 0 &&
			wcscmp(findData.cFileName, L".") != 0) {
			FindClose(hFind);
			DbgPrint(L"\tDirectory is not empty: %s\n", findData.cFileName);
			return STATUS_DIRECTORY_NOT_EMPTY;
		}
	} while (FindNextFile(hFind, &findData) != 0);

	DWORD error = GetLastError();

	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorMoveFile(LPCWSTR FileName, // existing file name
	LPCWSTR NewFileName, BOOL ReplaceIfExisting,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	WCHAR newFilePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD bufferSize;
	BOOL result;
	size_t newFilePathLen;

	PFILE_RENAME_INFO renameInfo = NULL;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);
	if (wcslen(NewFileName) && NewFileName[0] != ':') {
		GetFilePath(newFilePath, DOKAN_MAX_PATH, NewFileName, DokanFileInfo);
	} else {
		// For a stream rename, FileRenameInfo expect the FileName param without the filename
		// like :<stream name>:<stream type>
		wcsncpy_s(newFilePath, DOKAN_MAX_PATH, NewFileName, wcslen(NewFileName));
	}

	DbgPrint(L"MoveFile %s -> %s\n\n", filePath, newFilePath);
	//==========================================================
	//VER EL PATH
	//wprintf(L"Path: %s, Op: MoveFile\n", file_path);
	//wprintf(L"NewPath: %s, Op: MoveFile\n", newFilePath);
	//==========================================================
	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	newFilePathLen = wcslen(newFilePath);

	// the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
	// the end, so that
	// accounts for the null terminator

	bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) + newFilePathLen * sizeof(newFilePath[0]));

	renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
	if (!renameInfo) {
		return STATUS_BUFFER_OVERFLOW;
	}
	ZeroMemory(renameInfo, bufferSize);

	renameInfo->ReplaceIfExists = ReplaceIfExisting ? TRUE : FALSE; // some warning about converting BOOL to BOOLEAN
	renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
	renameInfo->FileNameLength = (DWORD)newFilePathLen * sizeof(newFilePath[0]); // they want length in bytes

	wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

	result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo, bufferSize);

	free(renameInfo);

	if (result) {
		return STATUS_SUCCESS;
	} else {
		DWORD error = GetLastError();
		DbgPrint(L"\tMoveFile error = %u\n", error);
		return DokanNtStatusFromWin32(error);
	}
}

static NTSTATUS DOKAN_CALLBACK MirrorLockFile(LPCWSTR FileName,
	LONGLONG ByteOffset,
	LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER offset;
	LARGE_INTEGER length;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"LockFile %s\n", filePath);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (!LockFile(handle, offset.LowPart, offset.HighPart, length.LowPart, length.HighPart)) {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\tsuccess\n\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile(
	LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER offset;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"SetEndOfFile %s, %I64d\n", filePath, ByteOffset);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	offset.QuadPart = ByteOffset;
	if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		DbgPrint(L"\tSetFilePointer error: %d, offset = %I64d\n\n", error, ByteOffset);
		return DokanNtStatusFromWin32(error);
	}

	if (!SetEndOfFile(handle)) {
		DWORD error = GetLastError();
		DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize(
	LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER fileSize;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"SetAllocationSize %s, %I64d\n", filePath, AllocSize);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	if (GetFileSizeEx(handle, &fileSize)) {
		if (AllocSize < fileSize.QuadPart) {
			fileSize.QuadPart = AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
				DWORD error = GetLastError();
				DbgPrint(L"\tSetAllocationSize: SetFilePointer eror: %d, offset = %I64d\n\n", error, AllocSize);
				return DokanNtStatusFromWin32(error);
			}
			if (!SetEndOfFile(handle)) {
				DWORD error = GetLastError();
				DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
				return DokanNtStatusFromWin32(error);
			}
		}
	} else {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes(
	LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);

	WCHAR filePath[DOKAN_MAX_PATH];

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"SetFileAttributes %s 0x%x\n", filePath, FileAttributes);

	if (FileAttributes != 0) {
		if (!SetFileAttributes(filePath, FileAttributes)) {
			DWORD error = GetLastError();
			DbgPrint(L"\terror code = %d\n\n", error);
			return DokanNtStatusFromWin32(error);
		}
	} else {
		// case FileAttributes == 0 :
		// MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
		// because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
		DbgPrint(L"Set 0 to FileAttributes means MUST NOT be changed. Didn't call SetFileAttributes function. \n");
	}

	DbgPrint(L"\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorSetFileTime(LPCWSTR FileName, CONST FILETIME* CreationTime,
	CONST FILETIME* LastAccessTime, CONST FILETIME* LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"SetFileTime %s\n", filePath);

	handle = (HANDLE)DokanFileInfo->Context;

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorUnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER length;
	LARGE_INTEGER offset;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"UnlockFile %s\n", filePath);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (!UnlockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
		length.HighPart)) {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\tsuccess\n\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
	PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	BOOLEAN requestingSaclInfo;

	UNREFERENCED_PARAMETER(DokanFileInfo);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"GetFileSecurity %s\n", filePath);

	MirrorCheckFlag(*SecurityInformation, FILE_SHARE_READ);
	MirrorCheckFlag(*SecurityInformation, OWNER_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, GROUP_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, SACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, LABEL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

	requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
		(*SecurityInformation & BACKUP_SECURITY_INFORMATION));

	if (!g_HasSeSecurityPrivilege) {
		*SecurityInformation &= ~SACL_SECURITY_INFORMATION;
		*SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
	}

	DbgPrint(L"  Opening new handle with READ_CONTROL access\n");
	HANDLE handle = CreateFile(
		filePath,
		READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
			? ACCESS_SYSTEM_SECURITY
			: 0),
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL, // security attribute
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
		NULL);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		int error = GetLastError();
		return DokanNtStatusFromWin32(error);
	}

	if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
		BufferLength, LengthNeeded)) {
		int error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER) {
			DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
			CloseHandle(handle);
			return STATUS_BUFFER_OVERFLOW;
		} else {
			DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
			CloseHandle(handle);
			return DokanNtStatusFromWin32(error);
		}
	}

	// Ensure the Security Descriptor Length is set
	DWORD securityDescriptorLength = GetSecurityDescriptorLength(SecurityDescriptor);
	DbgPrint(L"  GetUserObjectSecurity return true,  *LengthNeeded = securityDescriptorLength \n");
	*LengthNeeded = securityDescriptorLength;

	CloseHandle(handle);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
	PDOKAN_FILE_INFO DokanFileInfo) {
	HANDLE handle;
	WCHAR filePath[DOKAN_MAX_PATH];

	UNREFERENCED_PARAMETER(SecurityDescriptorLength);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"SetFileSecurity %s\n", filePath);

	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return STATUS_INVALID_HANDLE;
	}

	if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
		int error = GetLastError();
		DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
		return DokanNtStatusFromWin32(error);
	}
	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation(
	LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo) {

	UNREFERENCED_PARAMETER(DokanFileInfo);

	WCHAR volumeRoot[4];
	DWORD fsFlags = 0;

	// Set the name of the volume shown in file explorer
	if (volume_names [THREAD_INDEX]) {
		wcscpy_s(VolumeNameBuffer, VolumeNameSize, volume_names[THREAD_INDEX]);
	} else {
		wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"DOKAN");
	}

	if (VolumeSerialNumber)
		*VolumeSerialNumber = 0x19831116;
	if (MaximumComponentLength)
		*MaximumComponentLength = 255;
	if (FileSystemFlags) {
		*FileSystemFlags = FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;
		if (g_CaseSensitive)
			*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
	}

	volumeRoot[0] = RootDirectory[THREAD_INDEX][0];
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';

	if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, MaximumComponentLength, &fsFlags, FileSystemNameBuffer, FileSystemNameSize)) {
		if (FileSystemFlags)
			*FileSystemFlags &= fsFlags;

		if (MaximumComponentLength) {
			DbgPrint(L"GetVolumeInformation: max component length %u\n",
				*MaximumComponentLength);
		}
		if (FileSystemNameBuffer) {
			DbgPrint(L"GetVolumeInformation: file system name %s\n",
				FileSystemNameBuffer);
		}
		if (FileSystemFlags) {
			DbgPrint(L"GetVolumeInformation: got file system flags 0x%08x,"
				L" returning 0x%08x\n",
				fsFlags, *FileSystemFlags);
		}
	} else {
		DbgPrint(L"GetVolumeInformation: unable to query underlying fs, using defaults.  Last error = %u\n", GetLastError());

		// File system name could be anything up to 10 characters.
		// But Windows check few feature availability based on file system name.
		// For this, it is recommended to set NTFS or FAT here.
		wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
	}

	return STATUS_SUCCESS;
}


// Uncomment the function and set dokanOperations.GetDiskFreeSpace to personalize disk space
/*
static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
	PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
	PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  *FreeBytesAvailable = (ULONGLONG)(512 * 1024 * 1024);
  *TotalNumberOfBytes = 9223372036854775807;
  *TotalNumberOfFreeBytes = 9223372036854775807;

  return STATUS_SUCCESS;
}
*/

static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
	PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
	PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DWORD SectorsPerCluster;
	DWORD BytesPerSector;
	DWORD NumberOfFreeClusters;
	DWORD TotalNumberOfClusters;
	WCHAR DriveLetter[3] = { 'C', ':', 0 };
	PWCHAR RootPathName;

	if (RootDirectory[THREAD_INDEX][0] == L'\\') { // UNC as Root
		RootPathName = RootDirectory[THREAD_INDEX ];
	} else {
		DriveLetter[0] = RootDirectory[THREAD_INDEX][0];
		RootPathName = DriveLetter;
	}

	GetDiskFreeSpace(RootPathName, &SectorsPerCluster, &BytesPerSector,
		&NumberOfFreeClusters, &TotalNumberOfClusters);
	*FreeBytesAvailable =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	*TotalNumberOfFreeBytes =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	*TotalNumberOfBytes =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * TotalNumberOfClusters;
	return STATUS_SUCCESS;
}


///////////////// Here was the comment, the struct _IO_STATUS_BLOCK and the NtQueryInformationFile() function header (but no definition)


NTSTATUS DOKAN_CALLBACK
MirrorFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo) {
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE hFind;
	WIN32_FIND_STREAM_DATA findData;
	DWORD error;
	int count = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName, DokanFileInfo);

	DbgPrint(L"FindStreams :%s\n", filePath);

	hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	FillFindStreamData(&findData, DokanFileInfo);
	count++;

	while (FindNextStreamW(hFind, &findData) != 0) {
		FillFindStreamData(&findData, DokanFileInfo);
		count++;
	}

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_HANDLE_EOF) {
		DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\tFindStreams return %d entries in %s\n\n", count, filePath);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorMounted(PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DbgPrint(L"Mounted\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorUnmounted(PDOKAN_FILE_INFO DokanFileInfo) {
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DbgPrint(L"Unmounted\n");
	return STATUS_SUCCESS;
}

#pragma warning(pop)
