
/////  FILE INCLUDES  /////

#include "main.h"
#include "context.h"
#include "sharing_app.h"
#include "wrapper_dokan.h"
#include "wrapper_winfsp.h"



/////  FUNCTION DEFINITIONS  /////

int main(int argc, char* argv[]) {

	struct ThreadData th_data[NUM_LETTERS] = { 0 };
	HANDLE threads[NUM_LETTERS] = { 0 };

	system("cls");
	printf("\n");
	printf("\n");
	printf("          _____                       __          __        _     _ \n");
	printf("         / ____|                      \\ \\        / /       | |   | |\n");
	printf("        | (___   ___  ___ _   _ _ __ __\\ \\  /\\  / /__  _ __| | __| |\n");
	printf("         \\___ \\ / _ \\/ __| | | | '__/ _ \\ \\/  \\/ / _ \\| '__| |/ _` |\n");
	printf("         ____) |  __/ (__| |_| | | |  __/\\  /\\  / (_) | |  | | (_| |\n");
	printf("        |_____/ \\___|\\___|\\__,_|_|  \\___| \\/  \\/ \\___/|_|  |_|\\__,_|\n");
	printf("\n");
	/*
	It looks like this (but needs to duplicate backslashes to scape them)
	  _____                       __          __        _     _ 
	 / ____|                      \ \        / /       | |   | |
	| (___   ___  ___ _   _ _ __ __\ \  /\  / /__  _ __| | __| |
	 \___ \ / _ \/ __| | | | '__/ _ \ \/  \/ / _ \| '__| |/ _` |
	 ____) |  __/ (__| |_| | | |  __/\  /\  / (_) | |  | | (_| |
	|_____/ \___|\___|\__,_|_|  \___| \/  \/ \___/|_|  |_|\__,_|

	*/

	// Fill the table of equivalences between harddiskvolumes and letters
	initLetterDeviceMapping();

	// Load context from config.json
	loadContext();

	// Print the context
	printContext();

	// For each folder create and launch a thread and make it call threadDokan() or threadWinFSP()
	for (int i = 0; i < _msize(ctx.folders) / sizeof(struct Folder*); i++) {
	//for (int i = 0; i < 1; i++) {
		th_data[i].index = i;
		th_data[i].path = ctx.folders[i]->path;
		th_data[i].letter = ctx.folders[i]->mount_point;
		th_data[i].name = ctx.folders[i]->name;
		th_data[i].protection = ctx.folders[i]->protection;

		switch (ctx.folders[i]->driver) {
			case DOKAN:
				threads[i] = CreateThread(NULL, 0, threadDokan, &th_data[i], 0, NULL);
				break;
			case WINFSP:
				threads[i] = CreateThread(NULL, 0, threadWinFSP, &th_data[i], 0, NULL);
				break;
			default:
				break;
		}
		Sleep(1000);
	}

	// Initialize the parameters for the challenges
	initChallenges();

	// Initialize the parameters for the ciphers
	initCiphers();

	// Forever loop checking for new pendrives
	Sleep(2000);

	// Sharing menu
	sharingMainMenu();
}


int threadDokan(struct ThreadData *th_data) {
	dokanMapAndLaunch(th_data->index, th_data->path, th_data->letter, th_data->name, th_data->protection);
	/*while (TRUE) {
		printf("Hello, Dokan thread with id=%d reporting alive.\n", th_data->index);
		Sleep(8000);
	}*/

	return 0;
}

int threadWinFSP(struct ThreadData *th_data) {
	winfspMapAndLaunch(th_data->index, th_data->path, th_data->letter, th_data->name, th_data->protection);		////////////////// TO DO UNCOMMENT
	PRINT("WinFSPMapAndLaunch parameters:   index=%2d     letter=%wc     path='%ws' \t\t\t (not implemented yet)\n", th_data->index, th_data->letter, th_data->path);

	/*while (TRUE) {
		printf("Hello, WinFSP thread with id=%d reporting alive.\n", th_data->index);
		Sleep(8000);
	}*/

	return 0;
}



/**
* Fills the letter_device_table global variable.
*/
void initLetterDeviceMapping() {
	DWORD logical_drives_mask = 0;
	int count = 0;
	WCHAR tmp_str[3] = L" :";
	int index = 0;

	logical_drives_mask = GetLogicalDrives();

	//printf("logical_drives_mask (in hex): %X\n", logical_drives_mask);
	for (size_t i = 0; i < NUM_LETTERS; i++) {
		if (logical_drives_mask & (1 << i)) {
			count++;
		}
	}

	letter_device_table = malloc(count * sizeof(struct LetterDeviceMap));
	if (letter_device_table) {
		index = 0;
		for (size_t j = 0; j < NUM_LETTERS; j++) {
			if (logical_drives_mask & (1 << j)) {
				#pragma warning(suppress: 6386)
				letter_device_table[index].letter = (WCHAR)('A' + j);
				#pragma warning(suppress: 6385)
				tmp_str[0] = letter_device_table[index].letter;
				if (QueryDosDeviceW(tmp_str, letter_device_table[index].device, MAX_PATH) == 0) {
					fprintf(stderr, "ERROR: device path translation of letter %wc: is longer than %d.\n", letter_device_table[index].letter, MAX_PATH);
				}
				index++;
			}
		}
	} else {
		fprintf(stderr, "ERROR: failed to allocate necessary memory.\n");
		exit(1);
	}

	// print table
	PRINT("\nletter_device_table:\n");
	for (size_t i = 0; i < count; i++) {
		PRINT("%wc: --> %ws\n", letter_device_table[i].letter, letter_device_table[i].device);
	}
}

void initChallenges() {
	typedef int(__stdcall* init_func_type)(struct ChallengeEquivalenceGroup*, struct Challenge*);

	int result = 0;
	init_func_type init_func;


	for (size_t i = 0; i < _msize(ctx.groups) / sizeof(struct ChallengeEquivalenceGroup*); i++) {
		for (size_t j = 0; j < _msize(ctx.groups[i]->challenges) / sizeof(struct Challenge*); j++) {
			// define function pointer corresponding with init() input and output types
			init_func = (init_func_type)GetProcAddress(ctx.groups[i]->challenges[j]->lib_handle, "init");

			// Add parameters if necessary
			if (init_func!=NULL) {
				result = init_func(ctx.groups[i], ctx.groups[i]->challenges[j]);
				if (result != 0) {
					PRINT("WARNING: error trying to initialize the challenge '%ws'\n", ctx.groups[i]->challenges[j]->file_name);
				} else {
					break;		// Stop initializing more challenges in the group when one is already working
				}
			} else{
				PRINT("WARNING: error accessing the address to the init() function of the challenge '%ws' (error: %d)\n", ctx.groups[i]->challenges[j]->file_name, GetLastError());
			}
		}
	}
}


void initCiphers() {
	typedef int(__stdcall* init_func_type)(struct Cipher*);

	int result = 0;
	init_func_type init_func;

	for (size_t i = 0; i < _msize(ctx.ciphers) / sizeof(struct Cipher*); i++) {
		// define function pointer corresponding with init() input and output types
		init_func = (init_func_type)GetProcAddress(ctx.ciphers[i]->lib_handle, "init");

		// Add parameters if necessary
		if (init_func != NULL) {
			result = init_func(ctx.ciphers[i]);
			if (result != 0) {
				PRINT("WARNING: error trying to initialize the cipher '%ws'\n", ctx.ciphers[i]->file_name);
			} else {
				break;		// Stop initializing more challenges in the group when one is already working
			}
		} else {
			PRINT("WARNING: error accessing the address to the init() function of the cipher '%ws' (error: %d)\n", ctx.ciphers[i]->file_name, GetLastError());
		}
	}
}
