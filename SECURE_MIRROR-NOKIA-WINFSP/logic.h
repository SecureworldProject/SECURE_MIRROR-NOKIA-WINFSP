#ifndef LOGIC_H
#define LOGIC_H

/////  FILE INCLUDES  /////

#include "dokan.h"
#include <winfsp.h>
#include "context.h"
#include "winnt.h"
#include <psapi.h>
#include "context.h"
#include "wrapper_dokan.h"
#include "wrapper_winfsp.h"




/////  FUNCTION PROTOTYPES  /////

enum Operation operationAddition(enum Operation op1, enum Operation op2);
enum Operation getOpSyncFolder(enum IrpOperation irp_op, WCHAR file_path[]);
DWORD getFileSize(uint64_t* file_size, HANDLE handle, WCHAR* file_path);

// Logic functions

BOOL preCreateLogic(WCHAR file_path_param[], WCHAR* full_app_path);

int preReadLogic(
	uint64_t file_size, enum Operation op,
	LPVOID* orig_buffer, DWORD* orig_buffer_length, LPDWORD* orig_read_length, LONGLONG* orig_offset,
	LPVOID*  aux_buffer, DWORD*  aux_buffer_length, LPDWORD*  aux_read_length, LONGLONG*  aux_offset
);

//int postReadLogic(enum Operation op, WCHAR file_path[], LPCVOID* in_buffer, DWORD* buffer_length, LPDWORD* bytes_done, LONGLONG* offset, struct Protection* protection, LPCVOID out_buffer);
int postReadLogic(
	uint64_t file_size, enum Operation op, struct Protection* protection, HANDLE handle,
	LPVOID* orig_buffer, DWORD* orig_buffer_length, LPDWORD* orig_read_length, LONGLONG* orig_offset,
	LPVOID*  aux_buffer, DWORD*  aux_buffer_length, LPDWORD*  aux_read_length, LONGLONG*  aux_offset
);

//int preWriteLogic(enum Operation op, WCHAR file_path[], LPCVOID* in_buffer, DWORD* bytes_to_write, LPDWORD* bytes_written, LONGLONG* offset, struct Protection* protection, LPCVOID out_buffer);
int preWriteLogic(
	uint64_t* file_size, enum Operation op, WCHAR* file_path, struct Protection* protection, HANDLE handle, UCHAR write_to_eof,
	LPCVOID* orig_buffer, DWORD* orig_bytes_to_write, LPDWORD* orig_bytes_written, LONGLONG* orig_offset,
	LPVOID*   aux_buffer, DWORD*  aux_bytes_to_write, LPDWORD*  aux_bytes_written, LONGLONG*  aux_offset
);

int postWriteLogic(
	uint64_t* file_size, enum Operation op, WCHAR* file_path, struct Protection* protection, HANDLE handle, UCHAR write_to_eof,
	LPCVOID* orig_buffer, DWORD* orig_bytes_to_write, LPDWORD* orig_bytes_written, LONGLONG* orig_offset,
	LPVOID*   aux_buffer, DWORD*  aux_bytes_to_write, LPDWORD*  aux_bytes_written, LONGLONG*  aux_offset
);


#endif //!LOGIC_H
