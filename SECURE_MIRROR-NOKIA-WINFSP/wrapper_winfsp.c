

#include <winfsp.h>
#include <strsafe.h>
#include <Psapi.h>
 
//includes propios-----------------------------------------------------------------------------------------------
#include "config.h"
#include "context.h"
#include "wrapper_winfsp.h"
#include "main.h"
#include "logic.h"
//================================================================================================================
/////  DEFINITIONS  /////


#define PROGNAME                        "passthrough"
#define ALLOCATION_UNIT                 4096
#define FULLPATH_SIZE                   (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define info(format, ...)               FspServiceLog(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define warn(format, ...)               FspServiceLog(EVENTLOG_WARNING_TYPE, format, __VA_ARGS__)
#define fail(format, ...)               FspServiceLog(EVENTLOG_ERROR_TYPE, format, __VA_ARGS__)

#define ConcatPath(Ptfs, FN, FP)        (0 == StringCbPrintfW(FP, sizeof FP, L"%s%s", Ptfs->Path, FN))
#define HandleFromContext(FC)           (((PTFS_FILE_CONTEXT *)(FC))->Handle)
//------------------------------------------------------------------------------------------------------



/////  GLOBAL VARIABLES  /////


typedef struct
{
    FSP_FILE_SYSTEM *FileSystem;
    PWSTR Path;
} PTFS;



typedef struct
{
    HANDLE Handle;
    PVOID DirBuffer;
} PTFS_FILE_CONTEXT;

// This macro uses a parameter name from passthrough functions (only works inside them)
#define THREAD_INDEX FileSystem ->thread_index
//===================================================================================================

BOOL g_SecureLogs;	//Variable para logs de SecureWorld
static WCHAR RootDirectory[NUM_LETTERS][FULLPATH_SIZE] = { L"C:" };
static WCHAR MountPoint[NUM_LETTERS][FULLPATH_SIZE] = { L"M:\\" };
static WCHAR UNCName[NUM_LETTERS][FULLPATH_SIZE] = { L"" };
static WCHAR* volume_names[NUM_LETTERS] = { NULL };
//static struct VolumeInfo* volume_info[NUM_LETTERS] = { NULL };
// TO DO protections here instead of Cipher or others
static struct Protection* protections[NUM_LETTERS] = { NULL };
HANDLE hprocess;     ////ADD/////////////////


/////  FUNCTION PROTOTYPES  /////
WCHAR* getAppPathWinfsp();

static NTSTATUS GetFileInfoInternal(HANDLE Handle, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem, FSP_FSCTL_VOLUME_INFO* VolumeInfo);
static NTSTATUS SetVolumeLabel_(FSP_FILE_SYSTEM* FileSystem, PWSTR VolumeLabel, FSP_FSCTL_VOLUME_INFO* VolumeInfo);
static NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM* FileSystem, PWSTR FileName, PUINT32 PFileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize);
static NTSTATUS Create(FSP_FILE_SYSTEM* FileSystem, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS Open(FSP_FILE_SYSTEM* FileSystem, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess, PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS Overwrite(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO* FileInfo);
static VOID Cleanup(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, ULONG Flags);
static VOID Close(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext0);
static NTSTATUS Read(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred);
static NTSTATUS Write(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length, BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo, PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO* FileInfo);
NTSTATUS Flush(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, UINT32 FileAttributes, UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime, UINT64 ChangeTime, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS SetFileSize(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, UINT64 NewSize, BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo);
static NTSTATUS Rename(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists);
static NTSTATUS GetSecurity(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize);
static NTSTATUS SetSecurity(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor);
static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext0, PWSTR Pattern, PWSTR Marker, PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred);
static NTSTATUS SetDelete(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, BOOLEAN DeleteFile);
static FSP_FILE_SYSTEM_INTERFACE PtfsInterface =
{
    .GetVolumeInfo = GetVolumeInfo,            // modified
    .SetVolumeLabel = SetVolumeLabel_,        // modified
    .GetSecurityByName = GetSecurityByName,
    .Create = Create,                        // modified
    .Open = Open,                            // modified to capture PID also can be done in create
    .Overwrite = Overwrite,
    .Cleanup = Cleanup,
    .Close = Close,
    .Read = Read,                           // modified
    .Write = Write,                        // modified
    .Flush = Flush,
    .GetFileInfo = GetFileInfo,
    .SetBasicInfo = SetBasicInfo,
    .SetFileSize = SetFileSize,
    .Rename = Rename,
    .GetSecurity = GetSecurity,
    .SetSecurity = SetSecurity,
    .ReadDirectory = ReadDirectory,
    .SetDelete = SetDelete,
};
static VOID PtfsDelete(PTFS* Ptfs); 
static NTSTATUS EnableBackupRestorePrivileges(VOID);
static ULONG wcstol_deflt(wchar_t* w, ULONG deflt);
static NTSTATUS SvcStart(FSP_SERVICE* Service, ULONG argc, PWSTR* argv);
static NTSTATUS SvcStop(FSP_SERVICE* Service);

/////  FUNCTION DEFINITIONS  /////

int winfspMapAndLaunch(int index, WCHAR* path, WCHAR letter, WCHAR* volume_name, struct Protection* protection) {
    FSP_FILE_SYSTEM* FileSystem;
    PRINT("winfspMapAndLaunchMapAndLaunch parameters:    index=%2d     letter=%wc     path='%ws'\n", index, letter, path);

    // Fill
    FileSystem->thread_index = index;
    wcscpy_s(RootDirectory[index], sizeof(RootDirectory[index]) / sizeof(WCHAR), path);

    WCHAR letter_and_null[2] = { L'\0', L'\0' };
    letter_and_null[0] = letter;
    wcscpy_s(MountPoint[index], 2, letter_and_null);
    FileSystem->MountPoint = MountPoint[index];

    protections[index] = protection;
    volume_names[index] = volume_name;
    
    
    static NTSTATUS PtfsCreate(PWSTR Path, PWSTR VolumePrefix, PWSTR MountPoint, UINT32 DebugFlags, PTFS * *PPtfs);
    int WinfspMain(int argc, wchar_t** argv);
}

WCHAR* getAppPathWinfsp() {
    HANDLE process_handle;
    WCHAR* process_full_path = NULL;
    DWORD process_full_path_length = 0;

    process_full_path_length = MAX_PATH;
    process_full_path = malloc(process_full_path_length * sizeof(WCHAR));
    if (process_full_path != NULL) {
        process_handle = hprocess;
        
        if (GetProcessImageFileNameW(process_handle, process_full_path, process_full_path_length) > 0) {
            CloseHandle(process_handle);
            return process_full_path;
        }
        CloseHandle(process_handle);
        free(process_full_path);
    }

    return NULL;
}


static NTSTATUS GetFileInfoInternal(HANDLE Handle, FSP_FSCTL_FILE_INFO *FileInfo)
{
    BY_HANDLE_FILE_INFORMATION ByHandleFileInfo;

    if (!GetFileInformationByHandle(Handle, &ByHandleFileInfo))
        return FspNtStatusFromWin32(GetLastError());

    FileInfo->FileAttributes = ByHandleFileInfo.dwFileAttributes;
    FileInfo->ReparseTag = 0;
    FileInfo->FileSize =
        ((UINT64)ByHandleFileInfo.nFileSizeHigh << 32) | (UINT64)ByHandleFileInfo.nFileSizeLow;
    FileInfo->AllocationSize = (FileInfo->FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    FileInfo->CreationTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftCreationTime)->QuadPart;
    FileInfo->LastAccessTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastAccessTime)->QuadPart;
    FileInfo->LastWriteTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastWriteTime)->QuadPart;
    FileInfo->ChangeTime = FileInfo->LastWriteTime;
    FileInfo->IndexNumber = 0;
    FileInfo->HardLinks = 0;

    return STATUS_SUCCESS;
}

static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem, FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    PTFS* Ptfs = (PTFS*)FileSystem->UserContext;
   // WCHAR Root[MAX_PATH];
    ULARGE_INTEGER TotalSize, FreeSize;


    if (!GetVolumePathName(Ptfs->Path, RootDirectory, THREAD_INDEX))
        return FspNtStatusFromWin32(GetLastError());

    if (!GetDiskFreeSpaceEx(RootDirectory, 0, &TotalSize, &FreeSize))
        return FspNtStatusFromWin32(GetLastError());

    VolumeInfo->TotalSize = TotalSize.QuadPart;
    VolumeInfo->FreeSize = FreeSize.QuadPart;

    return STATUS_SUCCESS;
}

static NTSTATUS SetVolumeLabel_(FSP_FILE_SYSTEM* FileSystem,
    PWSTR VolumeLabel,
    FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    // Set the name of the volume shown in file explorer
    if (volume_names[THREAD_INDEX]) {
        wcscpy_s(VolumeLabel, VolumeInfo->VolumeLabelLength , volume_names[THREAD_INDEX]);
        return STATUS_SUCCESS;
    }
    else {
        /* we do not support changing the volume label */
        return STATUS_INVALID_DEVICE_REQUEST;
    }
        
}
static NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    PTFS *Ptfs = (PTFS *)FileSystem->UserContext;
    WCHAR FullPath[FULLPATH_SIZE];
    HANDLE Handle;
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;
    DWORD SecurityDescriptorSizeNeeded;
    NTSTATUS Result;

    if (!ConcatPath(Ptfs, FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    Handle = CreateFileW(FullPath,
        FILE_READ_ATTRIBUTES | READ_CONTROL, 0, 0,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (INVALID_HANDLE_VALUE == Handle)
    {
        Result = FspNtStatusFromWin32(GetLastError());
        goto exit;
    }

    if (0 != PFileAttributes)
    {
        if (!GetFileInformationByHandleEx(Handle,
            FileAttributeTagInfo, &AttributeTagInfo, sizeof AttributeTagInfo))
        {
            Result = FspNtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PFileAttributes = AttributeTagInfo.FileAttributes;
    }

    if (0 != PSecurityDescriptorSize)
    {
        if (!GetKernelObjectSecurity(Handle,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded))
        {
            *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
            Result = FspNtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
    }

    Result = STATUS_SUCCESS;

exit:
    if (INVALID_HANDLE_VALUE != Handle)
        CloseHandle(Handle);

    return Result;
}

static NTSTATUS Create(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize,
    PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    PTFS *Ptfs = (PTFS *)FileSystem->UserContext;
    WCHAR FullPath[FULLPATH_SIZE];
    SECURITY_ATTRIBUTES SecurityAttributes;
    ULONG CreateFlags;
    PTFS_FILE_CONTEXT *FileContext;

    //-------------------------------------------------------------------------------------------------------------
    WCHAR* full_app_path;
    full_app_path = getAppPathWinfsp();


    if (preCreateLogic(FullPath, full_app_path)) {
        return STATUS_IO_PRIVILEGE_FAILED;						// TO DO complete
    }
    //--------------------------------------------------------------------------------------------------------------------*/

    if (!ConcatPath(Ptfs, FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    FileContext = malloc(sizeof *FileContext);
    if (0 == FileContext)
        return STATUS_INSUFFICIENT_RESOURCES;
    memset(FileContext, 0, sizeof *FileContext);

    SecurityAttributes.nLength = sizeof SecurityAttributes;
    SecurityAttributes.lpSecurityDescriptor = SecurityDescriptor;
    SecurityAttributes.bInheritHandle = FALSE;

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    if (CreateOptions & FILE_DELETE_ON_CLOSE)
        CreateFlags |= FILE_FLAG_DELETE_ON_CLOSE;

    if (CreateOptions & FILE_DIRECTORY_FILE)
    {
        /*
         * It is not widely known but CreateFileW can be used to create directories!
         * It requires the specification of both FILE_FLAG_BACKUP_SEMANTICS and
         * FILE_FLAG_POSIX_SEMANTICS. It also requires that FileAttributes has
         * FILE_ATTRIBUTE_DIRECTORY set.
         */
        CreateFlags |= FILE_FLAG_POSIX_SEMANTICS;
        FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else
        FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;

    if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    FileContext->Handle = CreateFileW(FullPath,
        GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &SecurityAttributes,
        CREATE_NEW, CreateFlags | FileAttributes, 0);
    if (INVALID_HANDLE_VALUE == FileContext->Handle)
    {
        free(FileContext);
        return FspNtStatusFromWin32(GetLastError());
    }

    *PFileContext = FileContext;

    return GetFileInfoInternal(FileContext->Handle, FileInfo);
}

static NTSTATUS Open(FSP_FILE_SYSTEM *FileSystem,
    PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo)
{
    PTFS *Ptfs = (PTFS *)FileSystem->UserContext;
    WCHAR FullPath[FULLPATH_SIZE];
    ULONG CreateFlags;
    PTFS_FILE_CONTEXT *FileContext;

    if (!ConcatPath(Ptfs, FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    FileContext = malloc(sizeof *FileContext);
    if (0 == FileContext)
        return STATUS_INSUFFICIENT_RESOURCES;
    memset(FileContext, 0, sizeof *FileContext);

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    if (CreateOptions & FILE_DELETE_ON_CLOSE)
        CreateFlags |= FILE_FLAG_DELETE_ON_CLOSE;

    FileContext->Handle = CreateFileW(FullPath,
        GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0,
        OPEN_EXISTING, CreateFlags, 0);
    if (INVALID_HANDLE_VALUE == FileContext->Handle)
    {
        free(FileContext);
        return FspNtStatusFromWin32(GetLastError());
    }

    *PFileContext = FileContext;
    //----------------------Captura del PID---------------------------------------------------------------------------------------
    
    hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, FspFileSystemOperationProcessId());
    //=================================================================================================================

    return GetFileInfoInternal(FileContext->Handle, FileInfo);
}

static NTSTATUS Overwrite(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, UINT32 FileAttributes, BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);
    FILE_BASIC_INFO BasicInfo = { 0 };
    FILE_ALLOCATION_INFO AllocationInfo = { 0 };
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;

    if (ReplaceFileAttributes)
    {
        if (0 == FileAttributes)
            FileAttributes = FILE_ATTRIBUTE_NORMAL;

        BasicInfo.FileAttributes = FileAttributes;
        if (!SetFileInformationByHandle(Handle,
            FileBasicInfo, &BasicInfo, sizeof BasicInfo))
            return FspNtStatusFromWin32(GetLastError());
    }
    else if (0 != FileAttributes)
    {
        if (!GetFileInformationByHandleEx(Handle,
            FileAttributeTagInfo, &AttributeTagInfo, sizeof AttributeTagInfo))
            return FspNtStatusFromWin32(GetLastError());

        BasicInfo.FileAttributes = FileAttributes | AttributeTagInfo.FileAttributes;
        if (BasicInfo.FileAttributes ^ FileAttributes)
        {
            if (!SetFileInformationByHandle(Handle,
                FileBasicInfo, &BasicInfo, sizeof BasicInfo))
                return FspNtStatusFromWin32(GetLastError());
        }
    }

    if (!SetFileInformationByHandle(Handle,
        FileAllocationInfo, &AllocationInfo, sizeof AllocationInfo))
        return FspNtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

static VOID Cleanup(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, PWSTR FileName, ULONG Flags)
{
    HANDLE Handle = HandleFromContext(FileContext);

    if (Flags & FspCleanupDelete)
    {
        CloseHandle(Handle);

        /* this will make all future uses of Handle to fail with STATUS_INVALID_HANDLE */
        HandleFromContext(FileContext) = INVALID_HANDLE_VALUE;
    }
}

static VOID Close(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext0)
{
    PTFS_FILE_CONTEXT *FileContext = FileContext0;
    HANDLE Handle = HandleFromContext(FileContext);

    CloseHandle(Handle);

    FspFileSystemDeleteDirectoryBuffer(&FileContext->DirBuffer);
    free(FileContext);
}

static NTSTATUS Read(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length,
    PULONG PBytesTransferred)
{
    HANDLE Handle = HandleFromContext(FileContext);
    OVERLAPPED Overlapped = { 0 }; ///REVISAR TIPO DE DATO DISTINTO DE DOKAN////////////////////////////

    Overlapped.Offset = (DWORD)Offset; ///REVISAR EN DOKAN COMENTADO////////////////////////////
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32); ///REVISAR EN DOCAN COMENTADO////////////////////////////

   
    //--------------------------------------------------------------------------------------
    WCHAR file_path[MAX_PATH];//add 
    // Create auxiliar parameters for internal modification of the operation (mark and possible block cipher)
    PVOID aux_buffer = NULL;
    ULONG aux_buffer_length = 0;
    PULONG aux_read_length = NULL;
    UINT64 aux_offset = 0;

    DWORD error_code = 0;

    WCHAR* full_app_path = NULL;
    enum Operation op1;
    enum Operation op2;
    enum Operation op_final = NOTHING;

    full_app_path = getAppPathWinfsp(FileSystem);
    PRINT("Op: Pasthrough READ FILE,   APP_Path: %ws,   FILE_path: %ws\n", full_app_path, file_path);

    op1 = getTableOperation(ON_READ, &full_app_path, MountPoint[THREAD_INDEX][0]);
    op2 = getOpSyncFolder(ON_READ, file_path);

    op_final = operationAddition(op1, op2);
    PRINT("Obtained operations: op1=%d, op2=%d, op_final=%d\n", op1, op2, op_final);

    // Get file size
    uint64_t file_size;
    error_code = getFileSize(&file_size, Handle, file_path);
    if (error_code != 0) {
        PRINT("ERROR getting file size\n");
        goto READ_CLEANUP;			// Handle case where file size cannot be obtained. Abort operation??
    }

    // Initialize new read variables with updated values adjusted for the mark and possible block cipher
    error_code = preReadLogic(
        file_size, op_final,
        &Buffer, &Length, &PBytesTransferred, &Offset,
        &aux_buffer, &aux_buffer_length, &aux_read_length, &aux_offset
    );
    if (error_code != 0) {
        PRINT("ERROR in preReadLogic\n");
        goto READ_CLEANUP;
    }


    //READ-----------------------------------------------------------------------
    if (!ReadFile(Handle, aux_buffer, aux_buffer_length, aux_read_length, aux_offset)) {
        return FspNtStatusFromWin32(GetLastError());
        DbgPrint(L"\tread error = %u, buffer length = %u, read length = %u\n\n", error_code, aux_buffer_length, *aux_read_length);
        goto READ_CLEANUP;
    }

    // Initialize new read variables with updated values adjusted for the mark and possible block cipher
    error_code = postReadLogic(
        file_size, op_final, protections[THREAD_INDEX], Handle,
        &Buffer, &Length, &PBytesTransferred, &Offset,
        &aux_buffer, &aux_buffer_length, &aux_read_length, &aux_offset
    );
    if (error_code != 0) {
        PRINT("ERROR in postReadLogic.\n");
        goto READ_CLEANUP;
    }

    DbgPrint(L"\tByte to read: %d, Byte read %d, offset %lld\n\n", Length, *PBytesTransferred, Offset);

    
READ_CLEANUP:
    if (Handle != NULL) {
        PRINT("close handle\n");
        CloseHandle(Handle);
    }
    if (aux_buffer != Buffer && aux_buffer != NULL) {
        PRINT("free(aux_buffer)\n");
        free(aux_buffer);
    }
    if (aux_read_length != PBytesTransferred && aux_read_length != NULL) {
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


static NTSTATUS Write(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length,
    BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo,
    PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);
    LARGE_INTEGER FileSize;
    OVERLAPPED Overlapped = { 0 };

    if (ConstrainedIo)
    {
        if (!GetFileSizeEx(Handle, &FileSize))//MIRAR AQU�
            return FspNtStatusFromWin32(GetLastError());

        if (Offset >= (UINT64)FileSize.QuadPart)
            return STATUS_SUCCESS;
        if (Offset + Length > (UINT64)FileSize.QuadPart)
            Length = (ULONG)((UINT64)FileSize.QuadPart - Offset);
    }

    Overlapped.Offset = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    //------ADD---------------------------------
    WCHAR file_path[MAX_PATH];
    // Create aux params---------------------------------------------------------------------------------
    PVOID aux_buffer = NULL;
    ULONG aux_bytes_to_write = 0;
    PULONG aux_bytes_written = NULL;
    UINT64 aux_offset = 0;

    DWORD error_code = 0;

    WCHAR* full_app_path = NULL;
    enum Operation op1;
    enum Operation op2;
    enum Operation op_final = NOTHING;

    full_app_path = getAppPathWinfsp (FileSystem);
    printf("Op: MIRROR WRITE FILE,   APP_Path: %ws,   FILE_path: %ws\n", full_app_path, file_path);

    op1 = getTableOperation(ON_WRITE, &full_app_path, MountPoint[THREAD_INDEX][0]); // Better directly create global variable with pointer to table in this mounted disk
    op2 = getOpSyncFolder(ON_WRITE, file_path);

    op_final = operationAddition(op1, op2);
    PRINT("Obtained operations: op1=%d, op2=%d, op_final=%d\n", op1, op2, op_final);

    // Get file size
    uint64_t file_size;
    error_code = getFileSize(&file_size, Handle, file_path);
    if (error_code != 0) {
        PRINT("ERROR getting file size\n");
        goto WRITE_CLEANUP;			// Handle case where file size cannot be obtained. Abort operation??
    }

    error_code = preWriteLogic(
        &file_size, op_final, file_path, protections[THREAD_INDEX], Handle, WriteToEndOfFile,
        &Buffer, &Length, &PBytesTransferred, &Offset,
        &aux_buffer, &aux_bytes_to_write, &aux_bytes_written, &aux_offset
    );
    if (error_code != 0) {
        PRINT("ERROR in preWriteLogic. error_code = %d\n", error_code);
        goto WRITE_CLEANUP;
    }

    DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", file_path, Offset, Length);

    //WRITE-------------------------
    if (!WriteFile(Handle, aux_buffer, aux_bytes_to_write, aux_bytes_written, &Overlapped)){
        return FspNtStatusFromWin32(GetLastError());
        DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n", error_code, Length, *PBytesTransferred);
        /*if (opened)
        CloseHandle(handle);
        return DokanNtStatusFromWin32(error);*/
        goto WRITE_CLEANUP; 
    }  else { 
        DbgPrint(L"\twrite %d, offset %I64d\n\n", *PBytesTransferred, Offset);
    }

    error_code = postWriteLogic(
        &file_size, op_final, file_path, protections[THREAD_INDEX], Handle, WriteToEndOfFile,
        &Buffer, &Length, &PBytesTransferred, &Offset,
        &aux_buffer, &aux_bytes_to_write, &aux_bytes_written, &aux_offset
    );
    if (error_code != 0) {
        PRINT("ERROR in postWriteLogic. error_code = %d\n", error_code);
        goto WRITE_CLEANUP;
    }


WRITE_CLEANUP:
    if (Handle != NULL) {
        CloseHandle(Handle);
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

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS Flush(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);

    /* we do not flush the whole volume, so just return SUCCESS */
    if (0 == Handle)
        return STATUS_SUCCESS;

    if (!FlushFileBuffers(Handle))
        return FspNtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);

    return GetFileInfoInternal(Handle, FileInfo);
}

static NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, UINT32 FileAttributes,
    UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime, UINT64 ChangeTime,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);
    FILE_BASIC_INFO BasicInfo = { 0 };

    if (INVALID_FILE_ATTRIBUTES == FileAttributes)
        FileAttributes = 0;
    else if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    BasicInfo.FileAttributes = FileAttributes;
    BasicInfo.CreationTime.QuadPart = CreationTime;
    BasicInfo.LastAccessTime.QuadPart = LastAccessTime;
    BasicInfo.LastWriteTime.QuadPart = LastWriteTime;
    //BasicInfo.ChangeTime = ChangeTime;

    if (!SetFileInformationByHandle(Handle,
        FileBasicInfo, &BasicInfo, sizeof BasicInfo))
        return FspNtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

static NTSTATUS SetFileSize(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, UINT64 NewSize, BOOLEAN SetAllocationSize,
    FSP_FSCTL_FILE_INFO *FileInfo)
{
    HANDLE Handle = HandleFromContext(FileContext);
    FILE_ALLOCATION_INFO AllocationInfo;
    FILE_END_OF_FILE_INFO EndOfFileInfo;

    if (SetAllocationSize)
    {
        /*
         * This file system does not maintain AllocationSize, although NTFS clearly can.
         * However it must always be FileSize <= AllocationSize and NTFS will make sure
         * to truncate the FileSize if it sees an AllocationSize < FileSize.
         *
         * If OTOH a very large AllocationSize is passed, the call below will increase
         * the AllocationSize of the underlying file, although our file system does not
         * expose this fact. This AllocationSize is only temporary as NTFS will reset
         * the AllocationSize of the underlying file when it is closed.
         */

        AllocationInfo.AllocationSize.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
            FileAllocationInfo, &AllocationInfo, sizeof AllocationInfo))
            return FspNtStatusFromWin32(GetLastError());
    }
    else
    {
        EndOfFileInfo.EndOfFile.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
            FileEndOfFileInfo, &EndOfFileInfo, sizeof EndOfFileInfo))
            return FspNtStatusFromWin32(GetLastError());
    }

    return GetFileInfoInternal(Handle, FileInfo);
}

static NTSTATUS Rename(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists)
{
    PTFS *Ptfs = (PTFS *)FileSystem->UserContext;
    WCHAR FullPath[FULLPATH_SIZE], NewFullPath[FULLPATH_SIZE];

    if (!ConcatPath(Ptfs, FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    if (!ConcatPath(Ptfs, NewFileName, NewFullPath))
        return STATUS_OBJECT_NAME_INVALID;

    if (!MoveFileExW(FullPath, NewFullPath, ReplaceIfExists ? MOVEFILE_REPLACE_EXISTING : 0))
        return FspNtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

static NTSTATUS GetSecurity(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize)
{
    HANDLE Handle = HandleFromContext(FileContext);
    DWORD SecurityDescriptorSizeNeeded;

    if (!GetKernelObjectSecurity(Handle,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded))
    {
        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
        return FspNtStatusFromWin32(GetLastError());
    }

    *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;

    return STATUS_SUCCESS;
}

static NTSTATUS SetSecurity(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext,
    SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    HANDLE Handle = HandleFromContext(FileContext);

    if (!SetKernelObjectSecurity(Handle, SecurityInformation, ModificationDescriptor))
        return FspNtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext0, PWSTR Pattern, PWSTR Marker,
    PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred)
{
    PTFS *Ptfs = (PTFS *)FileSystem->UserContext;
    PTFS_FILE_CONTEXT *FileContext = FileContext0;
    HANDLE Handle = HandleFromContext(FileContext);
    WCHAR FullPath[FULLPATH_SIZE];
    ULONG Length, PatternLength;
    HANDLE FindHandle;
    WIN32_FIND_DATAW FindData;
    union
    {
        UINT8 B[FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + MAX_PATH * sizeof(WCHAR)];
        FSP_FSCTL_DIR_INFO D;
    } DirInfoBuf;
    FSP_FSCTL_DIR_INFO *DirInfo = &DirInfoBuf.D;
    NTSTATUS DirBufferResult;

    DirBufferResult = STATUS_SUCCESS;
    if (FspFileSystemAcquireDirectoryBuffer(&FileContext->DirBuffer, 0 == Marker, &DirBufferResult))
    {
        if (0 == Pattern)
            Pattern = L"*";
        PatternLength = (ULONG)wcslen(Pattern);

        Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
        if (0 == Length)
            DirBufferResult = FspNtStatusFromWin32(GetLastError());
        else if (Length + 1 + PatternLength >= FULLPATH_SIZE)
            DirBufferResult = STATUS_OBJECT_NAME_INVALID;
        if (!NT_SUCCESS(DirBufferResult))
        {
            FspFileSystemReleaseDirectoryBuffer(&FileContext->DirBuffer);
            return DirBufferResult;
        }

        if (L'\\' != FullPath[Length - 1])
            FullPath[Length++] = L'\\';
        memcpy(FullPath + Length, Pattern, PatternLength * sizeof(WCHAR));
        FullPath[Length + PatternLength] = L'\0';

        FindHandle = FindFirstFileW(FullPath, &FindData);
        if (INVALID_HANDLE_VALUE != FindHandle)
        {
            do
            {
                memset(DirInfo, 0, sizeof *DirInfo);
                Length = (ULONG)wcslen(FindData.cFileName);
                DirInfo->Size = (UINT16)(FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + Length * sizeof(WCHAR));
                DirInfo->FileInfo.FileAttributes = FindData.dwFileAttributes;
                DirInfo->FileInfo.ReparseTag = 0;
                DirInfo->FileInfo.FileSize =
                    ((UINT64)FindData.nFileSizeHigh << 32) | (UINT64)FindData.nFileSizeLow;
                DirInfo->FileInfo.AllocationSize = (DirInfo->FileInfo.FileSize + ALLOCATION_UNIT - 1)
                    / ALLOCATION_UNIT * ALLOCATION_UNIT;
                DirInfo->FileInfo.CreationTime = ((PLARGE_INTEGER)&FindData.ftCreationTime)->QuadPart;
                DirInfo->FileInfo.LastAccessTime = ((PLARGE_INTEGER)&FindData.ftLastAccessTime)->QuadPart;
                DirInfo->FileInfo.LastWriteTime = ((PLARGE_INTEGER)&FindData.ftLastWriteTime)->QuadPart;
                DirInfo->FileInfo.ChangeTime = DirInfo->FileInfo.LastWriteTime;
                DirInfo->FileInfo.IndexNumber = 0;
                DirInfo->FileInfo.HardLinks = 0;
                memcpy(DirInfo->FileNameBuf, FindData.cFileName, Length * sizeof(WCHAR));

                if (!FspFileSystemFillDirectoryBuffer(&FileContext->DirBuffer, DirInfo, &DirBufferResult))
                    break;
            } while (FindNextFileW(FindHandle, &FindData));

            FindClose(FindHandle);
        }

        FspFileSystemReleaseDirectoryBuffer(&FileContext->DirBuffer);
    }

    if (!NT_SUCCESS(DirBufferResult))
        return DirBufferResult;

    FspFileSystemReadDirectoryBuffer(&FileContext->DirBuffer,
        Marker, Buffer, BufferLength, PBytesTransferred);

    return STATUS_SUCCESS;
}

static NTSTATUS SetDelete(FSP_FILE_SYSTEM *FileSystem,
    PVOID FileContext, PWSTR FileName, BOOLEAN DeleteFile)
{
    HANDLE Handle = HandleFromContext(FileContext);
    FILE_DISPOSITION_INFO DispositionInfo;

    DispositionInfo.DeleteFile = DeleteFile;

    if (!SetFileInformationByHandle(Handle,
        FileDispositionInfo, &DispositionInfo, sizeof DispositionInfo))
        return FspNtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

static VOID PtfsDelete(PTFS *Ptfs);

static NTSTATUS PtfsCreate(PWSTR Path, PWSTR VolumePrefix, PWSTR MountPoint, UINT32 DebugFlags,
    PTFS **PPtfs)
{
    WCHAR FullPath[MAX_PATH];
    ULONG Length;
    HANDLE Handle;
    FILETIME CreationTime;
    DWORD LastError;
    FSP_FSCTL_VOLUME_PARAMS VolumeParams;
    PTFS *Ptfs = 0;
    NTSTATUS Result;

    *PPtfs = 0;

    Handle = CreateFileW(
        Path, FILE_READ_ATTRIBUTES, 0, 0,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (INVALID_HANDLE_VALUE == Handle)
        return FspNtStatusFromWin32(GetLastError());

    Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
    if (0 == Length)
    {
        LastError = GetLastError();
        CloseHandle(Handle);
        return FspNtStatusFromWin32(LastError);
    }
    if (L'\\' == FullPath[Length - 1])
        FullPath[--Length] = L'\0';

    if (!GetFileTime(Handle, &CreationTime, 0, 0))
    {
        LastError = GetLastError();
        CloseHandle(Handle);
        return FspNtStatusFromWin32(LastError);
    }

    CloseHandle(Handle);

    /* from now on we must goto exit on failure */

    Ptfs = malloc(sizeof *Ptfs);
    if (0 == Ptfs)
    {
        Result = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    memset(Ptfs, 0, sizeof *Ptfs);

    Length = (Length + 1) * sizeof(WCHAR);
    Ptfs->Path = malloc(Length);
    if (0 == Ptfs->Path)
    {
        Result = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    memcpy(Ptfs->Path, FullPath, Length);

    memset(&VolumeParams, 0, sizeof VolumeParams);
    VolumeParams.SectorSize = ALLOCATION_UNIT;
    VolumeParams.SectorsPerAllocationUnit = 1;
    VolumeParams.VolumeCreationTime = ((PLARGE_INTEGER)&CreationTime)->QuadPart;
    VolumeParams.VolumeSerialNumber = 0;
    VolumeParams.FileInfoTimeout = 1000;
    VolumeParams.CaseSensitiveSearch = 0;
    VolumeParams.CasePreservedNames = 1;
    VolumeParams.UnicodeOnDisk = 1;
    VolumeParams.PersistentAcls = 1;
    VolumeParams.PostCleanupWhenModifiedOnly = 1;
    VolumeParams.PassQueryDirectoryPattern = 1;
    VolumeParams.FlushAndPurgeOnCleanup = 1;
    VolumeParams.UmFileContextIsUserContext2 = 1;
    if (0 != VolumePrefix)
        wcscpy_s(VolumeParams.Prefix, sizeof VolumeParams.Prefix / sizeof(WCHAR), VolumePrefix);
    wcscpy_s(VolumeParams.FileSystemName, sizeof VolumeParams.FileSystemName / sizeof(WCHAR),
        L"" PROGNAME);

    Result = FspFileSystemCreate(
        VolumeParams.Prefix[0] ? L"" FSP_FSCTL_NET_DEVICE_NAME : L"" FSP_FSCTL_DISK_DEVICE_NAME,
        &VolumeParams,
        &PtfsInterface,
        &Ptfs->FileSystem);
    if (!NT_SUCCESS(Result))
        goto exit;
    Ptfs->FileSystem->UserContext = Ptfs;

    Result = FspFileSystemSetMountPoint(Ptfs->FileSystem, MountPoint);
    if (!NT_SUCCESS(Result))
        goto exit;

    FspFileSystemSetDebugLog(Ptfs->FileSystem, DebugFlags);

    Result = STATUS_SUCCESS;

exit:
    if (NT_SUCCESS(Result))
        *PPtfs = Ptfs;
    else if (0 != Ptfs)
        PtfsDelete(Ptfs);

    return Result;
}

static VOID PtfsDelete(PTFS *Ptfs)
{
    if (0 != Ptfs->FileSystem)
        FspFileSystemDelete(Ptfs->FileSystem);

    if (0 != Ptfs->Path)
        free(Ptfs->Path);

    free(Ptfs);
}

static NTSTATUS EnableBackupRestorePrivileges(VOID)
{
    union
    {
        TOKEN_PRIVILEGES P;
        UINT8 B[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
    } Privileges;
    HANDLE Token;

    Privileges.P.PrivilegeCount = 2;
    Privileges.P.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Privileges.P.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(0, SE_BACKUP_NAME, &Privileges.P.Privileges[0].Luid) ||
        !LookupPrivilegeValueW(0, SE_RESTORE_NAME, &Privileges.P.Privileges[1].Luid))
        return FspNtStatusFromWin32(GetLastError());

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FspNtStatusFromWin32(GetLastError());

    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges.P, 0, 0, 0))
    {
        CloseHandle(Token);

        return FspNtStatusFromWin32(GetLastError());
    }

    CloseHandle(Token);

    return STATUS_SUCCESS;
}

static ULONG wcstol_deflt(wchar_t *w, ULONG deflt)
{
    wchar_t *endp;
    ULONG ul = wcstol(w, &endp, 0);
    return L'\0' != w[0] && L'\0' == *endp ? ul : deflt;
}

static NTSTATUS SvcStart(FSP_SERVICE *Service, ULONG argc, PWSTR *argv)
{
#define argtos(v)                       if (arge > ++argp) v = *argp; else goto usage
#define argtol(v)                       if (arge > ++argp) v = wcstol_deflt(*argp, v); else goto usage

    wchar_t **argp, **arge;
    PWSTR DebugLogFile = 0;
    ULONG DebugFlags = 0;
    PWSTR VolumePrefix = 0;
    PWSTR PassThrough = 0;
    PWSTR MountPoint = 0;
    HANDLE DebugLogHandle = INVALID_HANDLE_VALUE;
    WCHAR PassThroughBuf[MAX_PATH];
    PTFS *Ptfs = 0;
    NTSTATUS Result;

    for (argp = argv + 1, arge = argv + argc; arge > argp; argp++)
    {
        if (L'-' != argp[0][0])
            break;
        switch (argp[0][1])
        {
        case L'?':
            goto usage;
        case L'd':
            argtol(DebugFlags);
            break;
        case L'D':
            argtos(DebugLogFile);
            break;
        case L'm':
            argtos(MountPoint);
            break;
        case L'p':
            argtos(PassThrough);
            break;
        case L'u':
            argtos(VolumePrefix);
            break;
        default:
            goto usage;
        }
    }

    if (arge > argp)
        goto usage;

    if (0 == PassThrough && 0 != VolumePrefix)
    {
        PWSTR P;

        P = wcschr(VolumePrefix, L'\\');
        if (0 != P && L'\\' != P[1])
        {
            P = wcschr(P + 1, L'\\');
            if (0 != P &&
                (
                (L'A' <= P[1] && P[1] <= L'Z') ||
                (L'a' <= P[1] && P[1] <= L'z')
                ) &&
                L'$' == P[2])
            {
                StringCbPrintf(PassThroughBuf, sizeof PassThroughBuf, L"%c:%s", P[1], P + 3);
                PassThrough = PassThroughBuf;
            }
        }
    }

    if (0 == PassThrough || 0 == MountPoint)
        goto usage;

    EnableBackupRestorePrivileges();

    if (0 != DebugLogFile)
    {
        if (0 == wcscmp(L"-", DebugLogFile))
            DebugLogHandle = GetStdHandle(STD_ERROR_HANDLE);
        else
            DebugLogHandle = CreateFileW(
                DebugLogFile,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                0,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                0);
        if (INVALID_HANDLE_VALUE == DebugLogHandle)
        {
            fail(L"cannot open debug log file");
            goto usage;
        }

        FspDebugLogSetHandle(DebugLogHandle);
    }

    Result = PtfsCreate(PassThrough, VolumePrefix, MountPoint, DebugFlags, &Ptfs);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot create file system");
        goto exit;
    }

    Result = FspFileSystemStartDispatcher(Ptfs->FileSystem, 0);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot start file system");
        goto exit;
    }

    MountPoint = FspFileSystemMountPoint(Ptfs->FileSystem);

    info(L"%s%s%s -p %s -m %s",
        L"" PROGNAME,
        0 != VolumePrefix && L'\0' != VolumePrefix[0] ? L" -u " : L"",
            0 != VolumePrefix && L'\0' != VolumePrefix[0] ? VolumePrefix : L"",
        PassThrough,
        MountPoint);

    Service->UserContext = Ptfs;
    Result = STATUS_SUCCESS;

exit:
    if (!NT_SUCCESS(Result) && 0 != Ptfs)
        PtfsDelete(Ptfs);

    return Result;

usage:
    static wchar_t usage[] = L""
        "usage: %s OPTIONS\n"
        "\n"
        "options:\n"
        "    -d DebugFlags       [-1: enable all debug logs]\n"
        "    -D DebugLogFile     [file path; use - for stderr]\n"
        "    -u \\Server\\Share    [UNC prefix (single backslash)]\n"
        "    -p Directory        [directory to expose as pass through file system]\n"
        "    -m MountPoint       [X:|*|directory]\n";

    fail(usage, L"" PROGNAME);

    return STATUS_UNSUCCESSFUL;

#undef argtos
#undef argtol
}

static NTSTATUS SvcStop(FSP_SERVICE *Service)
{
    PTFS *Ptfs = Service->UserContext;

    FspFileSystemStopDispatcher(Ptfs->FileSystem);
    PtfsDelete(Ptfs);

    return STATUS_SUCCESS;
}

int WinfspMain(int argc, wchar_t **argv)
{
    
    if (!NT_SUCCESS(FspLoad(0)))
        return ERROR_DELAY_LOAD_FAILED;
    
    return FspServiceRun(L"" PROGNAME, SvcStart, SvcStop, 0);
}
