/////  FILE INCLUDES  /////


#include "context.h"
#include "string.h"
#include <ctype.h>
#include <Windows.h>
#include "main.h"




/////  FUNCTION DEFINITIONS  /////

/**
* Returns a newly allocated and initialized (path="", name="" and type=ANY) pointer to an app.
* If it is not possible to allocate memory, frees internal buffers and returns NULL.
*
* @return struct App* app
*		The initialized app pointer. May be NULL.
**/
static struct App* createApp() {
	struct App* app =  malloc(sizeof(struct App));
	if (app) {

		app->name = malloc(MAX_PATH * sizeof(WCHAR));
		if (app->name)
			memset(app->name, L'\0', MAX_PATH * sizeof(WCHAR));
		else
			goto _LABEL_FREE;

		app->path = malloc(MAX_PATH * sizeof(WCHAR));
		if (app->path)
			memset(app->path, L'\0', MAX_PATH * sizeof(WCHAR));
		else
			goto _LABEL_FREE;

		app->type = ANY;
	} else
		goto _LABEL_FREE;

	return app;

	_LABEL_FREE:
	if (app) {
		if (app->path) free(app->path);
		if (app->name) free(app->name);
		free(app);
	}
	return NULL;
}

/**
* Frees all the memory from the app pointer passed as parameter and all its fields.
*
* @param struct App** app
*		The pointer to the app pointer to be destroyed. The pointer to App is always nullified.
**/
static void destroyApp(struct App** app) {
	struct App* a = *app;

	if (a) {
		if (a->path) free(a->path);
		if (a->name) free(a->name);
		free(a);
	}
	a = NULL;
}


/**
* Gets the operation that has to be done when reading/writing by checking the corresponding OpTable with the app and filepath given.
*
* @param enum IrpOperation irp_operation
*		Determines if the operation needed is for a read or write.
* @param char* app_full_path
*		The full path (name and extension included) to the executable of the irp originating process.
* @param char* file_full_path
*		The full path (name and extension included) of the file which irp operation is about.
*
* @return enum Operation
*		The logic that must be done for the given irp operation, appfile
**/
enum Operation getTableOperation(enum IrpOperation irp_operation, WCHAR** app_full_path, WCHAR mount_point) {
	enum Operation *result_operation = NULL;
	struct OpTable* table = NULL;
	enum AppType app_type = ANY;
	//char disk_letter = '\0';

	// Gets the table to apply to the file path
	table = getTable(mount_point);

	// Gets the app_type for the given app_full_path
	if (*app_full_path != NULL) {
		formatPath(app_full_path);
		app_type = (getApp(*app_full_path))->type;
	}

	// Gets the disk for the given file path
	//disk_letter = getDiskType(file_full_path);

	// Gets the operation for the disk and app_type in the table given. The irp_operation is an enum that is used as index
	result_operation = getOperations(app_type, table);
	if (result_operation) {
		return result_operation[irp_operation];
	}

	return NOTHING;
}


inline struct OpTable* getTable(WCHAR mount_point) {
	//WCHAR letter = L'\0';

	// For the moment assume the path is good and then letter is position 0 of the string.
	//letter = file_full_path[4];
	//letter = towupper(letter);


	// Return the table from the context folder which MountPoint matches the letter
	for (int i = 0; i < _msize(ctx.folders) / sizeof(char*); i++) {
		if (ctx.folders[i]->mount_point == mount_point) {
			return ctx.folders[i]->protection->op_table;
		}
	}

	// Check if the letter is a pendrive
	for (int i = 0; i < wcslen(ctx.pendrive->mount_points); i++) {
		if (ctx.pendrive->mount_points[i] == mount_point) {
			return ctx.pendrive->protection->op_table;
		}
	}

	// If not found, return NULL (this should never happen)
	fprintf(stderr, "ERROR returning NULL in getTable().\n");
	return NULL;
}

inline struct App* getApp(WCHAR* app_full_path) {
	enum AppType app_type = ANY;
	struct App* app = NULL;
	WCHAR* tmp_str = NULL;
	size_t len = 0;
	BOOL match_found = FALSE;

	// Initialize an app
	app = createApp();
	if (app_full_path == NULL) {
		return app;
	}

	// Find last position of a forward slash, which divides string in "path" and "name" (e.g.:  C:/path/to/folder/name.exe)
	tmp_str = wcsrchr(app_full_path, L'\\');

	// Fill app path and name
	*tmp_str = L'\0';
	len = wcslen(app_full_path);
	wcscpy(app->path, app_full_path);
	app->path[len] = L'\\';
	app->path[len + 1] = L'\0';
	wcscpy(app->name, tmp_str + 1);

	// For every app in the list check if the path is the same
	for (int i = 0; !match_found && i < _msize(ctx.apps) / sizeof(struct App*); i++) {
		if (wcscmp(ctx.apps[i]->path, app->path) == 0) {
			match_found = TRUE;
			app->type = ctx.apps[i]->type;
			break;
		}
	}

	// For every app in the list check if the name is the same
	for (int i = 0; !match_found && i < _msize(ctx.apps) / sizeof(struct App*); i++) {
		if (wcscmp(ctx.apps[i]->name, app->name) == 0) {
			match_found = TRUE;
			app->type = ctx.apps[i]->type;
			break;
		}
	}

	return app;
}

__declspec(deprecated) inline WCHAR getDiskType(WCHAR* file_full_path) {
	// It can be '0' (sync folders), '1' (pendrives) or any letter ('a', 'b', 'c', etc.)
	WCHAR* tmp_str = NULL;
	WCHAR letter = L'\0';

	// Check if it is syncfolder
	for (int i = 0; i < _msize(ctx.sync_folders) / sizeof(WCHAR*); i++) {
		tmp_str = wcsstr(file_full_path, ctx.sync_folders[i]);
		if (tmp_str != NULL && tmp_str == file_full_path) {
			return L'0';			// It matches a syncfolder
		}
	}

	// Check if it is a pendrive
	letter = file_full_path[0];
	letter = towupper(letter);		// This should already have been done in formatPath()

	// Check if the letter is a pendrive
	for (int i = 0; i < wcslen(ctx.pendrive->mount_points); i++) {
		if (ctx.pendrive->mount_points[i] == letter) {
			return L'1';
		}
	}

	// It is a letter (file is not in a sync folder nor a pendrive)
	return letter;
}

inline enum Operation* getOperations(enum AppType app_type, struct OpTable* table) {
	enum Operation* operations = NULL;
	struct Tuple* tab_tuple_default = NULL;

	operations = malloc(NUM_IRP_OPERATIONS * sizeof(enum Operation));
	if (operations) {

		for (int i = 0; i < _msize(table->tuples) / sizeof(struct Tuple*); i++) {
			if (table->tuples[i]->app_type == app_type) {
				operations[ON_READ] = table->tuples[i]->on_read;
				operations[ON_WRITE] = table->tuples[i]->on_write;
				return operations;
			}
			if (table->tuples[i]->app_type == ANY) {
				tab_tuple_default = table->tuples[i];
			}
		}
		if (tab_tuple_default != NULL) {
			operations[ON_READ] = tab_tuple_default->on_read;
			operations[ON_WRITE] = tab_tuple_default->on_write;
		} else {
			free(operations);
			operations = NULL;
		}
	}

	return operations;
}

__declspec(deprecated) void formatPathOLD(char** full_path) {
	char* tmp_str = NULL;

	// WARNING!!!  read below
	// Paths may have many different writtings:
	//		- "X:\folder1\folder2\file.txt"
	//		- "\Device\Harddiskvolume1\folder1\folder2\file.txt"
	//		- "\Device\Harddisk0\Partition0\folder1\folder2\file.txt"
	//		- "\\?\Volume{a2b4c6d8-0000-0000-00000100000000000}\folder1\folder2\file.txt"
	// Appart from the different writtings there are additional problems:
	//		- May have forward or backward slashes.
	//		- May be preceded by "\\?\" or "\\.\".
	//		- May contain relative paths inside (like references to the same path "./" or to the parent directory "../").
	//		- If the path refers to a folder, it may or not contain a trailing slash.

	// Clear possible forward slashes into backward slashes
	tmp_str = strchr(*full_path, '/');
	while (tmp_str != NULL) {
		*tmp_str = '\\';
		tmp_str = strchr(*full_path, '/');
	}

	// TO DO MORE FORMATTING

	// Call GetFullPathName(). Normalices to absolute paths and removes the "./" and "../"
	// If it is directory to add trailing slash. Check with PathIsDirectoryA()
	//
	// Other possibility is to open a handle with the path and use function GetFinalPathNameByHandle()
}

int fromDeviceToLetter(WCHAR** full_path) {
	WCHAR* tmp_str = NULL;
	WCHAR* match_ptr;
	WCHAR* new_full_path;
	size_t initial_len;
	size_t device_len;

	// Clear possible forward slashes into backward slashes
	PRINT("Clearing slashes in '%ws'\n", *full_path);
	tmp_str = wcschr(*full_path, L'/');
	while (tmp_str != NULL) {
		*tmp_str = L'\\';
		tmp_str = wcschr(*full_path, L'/');
	}

	// Change Device path for DOS letter path
	PRINT("Looking for Device path match in '%ws'\n", *full_path);
	initial_len = wcslen(*full_path);
	for (size_t i = 0; i < _msize(letter_device_table) / sizeof(struct LetterDeviceMap); i++) {
		device_len = wcslen(letter_device_table[i].device);
		if (initial_len > device_len) {
			match_ptr = wcsstr(*full_path, letter_device_table[i].device);
			if (match_ptr && match_ptr == *full_path) {
				//PRINT("Match found, allocating %lld * sizeof(WCHAR)\n", (initial_len - device_len + 2 + 1));
				new_full_path = malloc((initial_len - device_len + 2 + 1) * sizeof(WCHAR));					// +2 for "X:" and +1 for null char
				if (new_full_path) {
					// Fill new full path
					//PRINT("Allocate success: Fill new full path\n");
					new_full_path[0] = letter_device_table[i].letter;
					#pragma warning(suppress: 6386)
					new_full_path[1] = L':';
					wcscpy(&(new_full_path[2]), &((*full_path)[device_len-1+1]));	// -1 because indexes start on 0 and +1 to start on the next slot
					// Free old full path
					//PRINT("Allocate success: Free old full path\n");
					free(*full_path);
					// Assign new full path
					//PRINT("Allocate success: Assign new full path\n");
					*full_path = new_full_path;
					return 0;
				} else {
					return 2;	// Could not allocate memory
				}
			}
		}
	}

	return 1;	// No matches
}

void formatPath(WCHAR** full_path) {
	HANDLE handle = NULL;
	WCHAR* new_full_path = NULL;
	DWORD result = 0;
	DWORD attributes_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS;


	PRINT("Function formatPath() starts with '%ws'\n", *full_path);
	if (wcsstr(*full_path, L"Device") != NULL) {	//== &((*full_path)[1])) {
		PRINT("Starting fromDeviceToLetter() function on '%ws'\n", *full_path);
		switch (fromDeviceToLetter(full_path)) {
			case 0:
				PRINT("New path is: %ws\n", *full_path);
				break;
			case 1:
				PRINT("No matches found\n");
				break;
			case 2:
				fprintf(stderr, "ERROR: could not allocate memory\n");
				break;
			default:
				fprintf(stderr, "ERROR: unknown error\n");
				break;
		}
	} else {
		PRINT("Skipping device to letter conversion...\n");
	}

	if (!PathFileExistsW(*full_path)) {
		fprintf(stderr, "ERROR: path does not exist.\n");
		printLastError(GetLastError());
		return;
	}

	/*if (PathIsDirectoryW(*full_path)) {
		PRINT("directory!!!!\n");
		attributes_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS;
	} else {
		PRINT("file!!!!\n");
		attributes_flags = FILE_ATTRIBUTE_NORMAL;
	}*/

	handle = CreateFileW(*full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, attributes_flags, NULL);

	if (handle != INVALID_HANDLE_VALUE) {
		result = GetFinalPathNameByHandleW(handle, new_full_path, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (result != 0) {
			new_full_path = malloc(result * sizeof(WCHAR));
			if (new_full_path) {
				if (result - 1 == GetFinalPathNameByHandleW(handle, new_full_path, result, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)) {
					free(*full_path);
					*full_path = new_full_path;
				} else {
					fprintf(stderr, "ERROR: something went wrong obtaining the path by handle (%lu)\n", GetLastError());
					free(new_full_path);
				}
			} else {
				fprintf(stderr, "ERROR: could not allocate memory\n");
			}
		} else {
			fprintf(stderr, "ERROR: something went wrong obtaining the path by handle (%lu)\n", GetLastError());
		}
		CloseHandle(handle);
	} else {
		fprintf(stderr, "ERROR: invalid file handle (%lu)\n", GetLastError());
	}

	PRINT("Function formatPath() ends with '%ws'\n", *full_path);
}

void printLastError(DWORD error_value){
	wchar_t err_buf[256];
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error_value, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err_buf, (sizeof(err_buf) / sizeof(wchar_t)), NULL);
	fprintf(stderr, "ErrorMessage=%ws\n", err_buf);
}
