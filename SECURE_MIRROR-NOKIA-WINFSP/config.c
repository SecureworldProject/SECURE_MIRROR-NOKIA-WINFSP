/*
* SecureWorld file config.c
* carga la configuración en el contexto usando un parser. contiene la función loadContext() y checkContext()
y otras posibles funciones auxiliares que necesite. El contexto incluye la carga operativa que luego condiciona
el comportamiento de la función logic().

Nokia Febrero 2021
*/

/////  FILE INCLUDES  /////

#include "config.h"
//#include "json.h"         // Already in config.h
//#include "context.h"      // Already in config.h
#include <sys/stat.h>
#include <stdio.h>
#include <inttypes.h>
//#include <stdint.h>       // Already in inttypes.h
#include <wchar.h>



/////  FUNCTION DEFINITIONS  /////


#pragma region Basic json testing functions (unused)

static void print_depth_shift(int depth) {
	int j;
	for (j = 0; j < depth; j++) {
		printf(" ");
	}
}

static void process_value(json_value* value, int depth);

static void process_object(json_value* value, int depth) {
	int length, x;
	if (value == NULL) {
		return;
	}
	length = value->u.object.length;

	for (x = 0; x < length; x++) {
		print_depth_shift(depth);
		//printf("object[%d].name = %s\n", x, value->u.object.values[x].name);
		process_value(value->u.object.values[x].value, depth + 1);
	}
}

static void process_array(json_value* value, int depth) {
	int length, x;
	if (value == NULL) {
		return;
	}
	length = value->u.array.length;
	//printf("Longitud del array %d\n", length);
	for (x = 0; x < length; x++) {
		process_value(value->u.array.values[x], depth);
	}
}

static void process_value(json_value* value, int depth) {
	if (value == NULL) {
		return;
	}

	if (value->type != json_object) {
		print_depth_shift(depth);
	}

	switch (value->type) {
	case json_none:
		printf("none\n");
		break;
	case json_object:
		process_object(value, depth + 1);
		break;
	case json_array:
		process_array(value, depth + 1);
		break;
	case json_integer:
		printf("int: %10" PRId64 "\n", value->u.integer);
		break;
	case json_double:
		printf("double: %f\n", value->u.dbl);
		break;
	case json_string:
		printf("string: %s\n", value->u.string.ptr);
		break;
	case json_boolean:
		printf("bool: %d\n", value->u.boolean);
		break;
	}
}

#pragma endregion


#pragma region Internal config.json processing functions

static void processProtection(struct Protection* ctx_value, json_value* value, int depth) {
	int dict_length, x, num_groups;

	dict_length = value->u.object.length;
	for (x = 0; x < dict_length; x++) {

		if (strcmp(value->u.object.values[x].name, "OpTable") == 0) {
			//PRINT1("OpTable id detected------\n");
			// This will be a OpTable pointer but for now it will hold the id, so force it as char pointer
			#pragma warning(suppress: 4133)
			ctx_value->op_table = (char*)malloc(sizeof(char) * ((value->u.object.values[x].value->u.string.length) + 1));
			if (ctx_value->op_table) {
				#pragma warning(suppress: 4133)
				strcpy(ctx_value->op_table, value->u.object.values[x].value->u.string.ptr);
				//PRINT("OpTable id copied++++++\n");
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[x].name, "ChallengeEqGroups") == 0) {
			//Este objeto es un array
			num_groups = value->u.object.values[x].value->u.array.length;
			if (num_groups <= 0) {          // Fixes warning C6386 (Visual Studio bug)
				ctx_value->challenge_groups = NULL;
			} else {
				#pragma warning(suppress: 4133)
				ctx_value->challenge_groups = (char**) malloc(num_groups * sizeof(char*));   // Allocate space for all pointers to char
				if (ctx_value->challenge_groups) {
					for (int i = 0; i < num_groups; i++) {
						#pragma warning(suppress: 4133)
						ctx_value->challenge_groups[i] = (char*) malloc(sizeof(char) * ((value->u.object.values[x].value->u.array.values[i]->u.string.length) + 1));
						if (ctx_value->challenge_groups[i]) {
							#pragma warning(suppress: 4133)
							strcpy(ctx_value->challenge_groups[i], value->u.object.values[x].value->u.array.values[i]->u.string.ptr);
						} // else --> The pointer is null because it was not possible to allocate memory
					}
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		}

		else if (strcmp(value->u.object.values[x].name, "Cipher") == 0) {
			ctx_value->cipher = malloc(sizeof(char) * ((value->u.object.values[x].value->u.string.length) + 1));
			if (ctx_value->cipher) {
				#pragma warning(suppress: 4133)
				strcpy(ctx_value->cipher, value->u.object.values[x].value->u.string.ptr);
			} // else --> The pointer is null because it was not possible to allocate memory
		}
	}

	// Allocate the key
	ctx_value->key = (struct KeyData*)malloc(sizeof(struct KeyData) * 1);
	struct KeyData* key = ctx_value->key;
	if (key) {
		key->size = 0;                                            // Obtain from config.json?
		key->data = (byte*)malloc(sizeof(byte) * key->size);      // Key data is allocated as many space as indicated by the size member of the struct
		key->expires = (time_t)0;                                 // Key expired in 1970
	} // else --> The pointer is null because it was not possible to allocate memory

}

static void processFolder(int index, json_value* value, int depth) {
	int dict_length, x;
	enum Driver driver;
	char* driver_str;
	json_value* protection_value;

	dict_length = value->u.object.length;
	for (x = 0; x < dict_length; x++) {

		if (strcmp(value->u.object.values[x].name, "Path") == 0) {
			ctx.folders[index]->path = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[x].value->u.string.length)+1));
			if (ctx.folders[index]->path) {
				mbstowcs(ctx.folders[index]->path, value->u.object.values[x].value->u.string.ptr, SIZE_MAX);
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[x].name, "MountPoint") == 0) {
			/*ctx.folders[index]->mount_point = (char*)malloc(sizeof(char) * ((value->u.object.values[x].value->u.string.length) + 1));
			if (ctx.folders[index]->mount_point) {
				strcpy(ctx.folders[index]->mount_point, value->u.object.values[x].value->u.string.ptr);
			} // else --> The pointer is null because it was not possible to allocate memory*/
			if (value->u.object.values[x].value->u.string.length >= 1) {
				ctx.folders[index]->mount_point = btowc(toupper(value->u.object.values[x].value->u.string.ptr[0]));
			} else {
				ctx.folders[index]->mount_point = L'\0'; // ERROR
				fprintf(stderr, "WARNING: incorrect MountPoint.\n");
			}
		}

		else if (strcmp(value->u.object.values[x].name, "Name") == 0) {
			ctx.folders[index]->name = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[x].value->u.string.length) + 1));
			if (ctx.folders[index]->name) {
				mbstowcs(ctx.folders[index]->name, value->u.object.values[x].value->u.string.ptr, SIZE_MAX);
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[x].name, "Driver") == 0) {
			driver_str = value->u.object.values[x].value->u.string.ptr;
			if (strcmp(driver_str, "WinFSP") == 0)          driver = WINFSP;
			else if (strcmp(driver_str, "DOKAN") == 0)      driver = DOKAN;
			else                                            driver = DOKAN;     // This is the default driver: Dokan
			ctx.folders[index]->driver = driver;
		}

		else if (strcmp(value->u.object.values[x].name, "Protection") == 0) {
			ctx.folders[index]->protection = (struct Protection*)malloc(sizeof(struct Protection));
			if (ctx.folders[index]->protection) {
				protection_value = value->u.object.values[x].value;
				processProtection(ctx.folders[index]->protection, protection_value, depth + 1);
			} // else --> The pointer is null because it was not possible to allocate memory
		}
	}
}

static void processFolders(json_value* value, int depth) {
	PRINT(" - processFolders() starts\n");
	int array_length;
	int array_pos = 0;
	int in_folder_length = 0;
	int in_folder_pos = 0;

	array_length = value->u.array.length;
	if (array_length <= 0) {        // Fixes warning C6386 (Visual Studio bug)
		ctx.folders = NULL;
	} else {
		ctx.folders = (struct Folder**)malloc(array_length * sizeof(struct Folder*));
		if (ctx.folders) {
			for (int i = 0; i < array_length; i++) {
				ctx.folders[i] = (struct Folder*)malloc(sizeof(struct Folder));
				if (ctx.folders[i]) {
					processFolder(i, value->u.array.values[i], depth);
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processFolders() ends\n");
}

static void processPendrive(json_value* value, int depth) {
	PRINT(" - processPendrive() starts\n");
	int dict_length, x;
	enum Driver driver;
	char* driver_str;
	json_value* protection_value;

	ctx.pendrive = (struct Pendrive*)malloc(sizeof(struct Pendrive));

	dict_length = value->u.object.length;
	for (x = 0; x < dict_length; x++) {

		if (strcmp(value->u.object.values[x].name, "MountPoints") == 0) {

			ctx.pendrive->mount_points = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[x].value->u.string.length) + 1));
			if (ctx.pendrive->mount_points) {
				//strcpy(ctx.pendrive->mount_points, value->u.object.values[x].value->u.string.ptr);
				for (size_t i = 0; i < value->u.object.values[x].value->u.string.length; i++) 		{
					ctx.pendrive->mount_points[i] = btowc(toupper(value->u.object.values[x].value->u.string.ptr[i]));
				}
				#pragma warning(suppress: 6386)
				ctx.pendrive->mount_points[value->u.object.values[x].value->u.string.length] = L'\0';
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[x].name, "Driver") == 0) {
			driver_str = value->u.object.values[x].value->u.string.ptr;
			if (strcmp(driver_str, "WinFSP") == 0)          driver = WINFSP;
			else if (strcmp(driver_str, "DOKAN") == 0)      driver = DOKAN;
			else                                            driver = DOKAN;     // This is the default driver: Dokan
			ctx.pendrive->driver = driver;
		}

		else if (strcmp(value->u.object.values[x].name, "Protection") == 0) {
			ctx.pendrive->protection = (struct Protection*)malloc(sizeof(struct Protection));
			if (ctx.pendrive->protection) {
				protection_value = value->u.object.values[x].value;
				processProtection(ctx.pendrive->protection, protection_value, depth + 1);
			} // else --> The pointer is null because it was not possible to allocate memory
		}
	}
	PRINT(" - processPendrive() ends\n");
}

static void processParentalControls(json_value* value, int depth) {
	PRINT(" - processParentalControls() starts\n");
	int array_length, dict_length, users_array_length, groups_array_length;
	json_value* array_value;

	array_length = value->u.array.length;
	if (array_length <= 0) {    // Fixes warning C6386 (Visual Studio bug)
		ctx.parentals = NULL;
	} else {
		ctx.parentals = (struct ParentalControl**)malloc(array_length * sizeof(struct ParentalControl*));
		if (ctx.parentals) {
			for (int i = 0; i < array_length; i++) {
				ctx.parentals[i] = (struct ParentalControl*)malloc(sizeof(struct ParentalControl));
				if (ctx.parentals[i]) {
					array_value = value->u.array.values[i];
					dict_length = array_value->u.object.length;
					for (int j = 0; j < dict_length; j++) {

						if (strcmp(array_value->u.object.values[j].name, "Folder") == 0) {
							ctx.parentals[i]->folder = (WCHAR*)malloc(sizeof(WCHAR) * ((array_value->u.object.values[j].value->u.string.length) + 1));
							if (ctx.parentals[i]->folder) {
								mbstowcs(ctx.parentals[i]->folder, array_value->u.object.values[j].value->u.string.ptr, SIZE_MAX);
							} // else --> The pointer is null because it was not possible to allocate memory
						}

						else if (strcmp(array_value->u.object.values[j].name, "Users") == 0) {
							users_array_length = array_value->u.object.values[j].value->u.array.length;
							if (users_array_length <= 0) {      // Fixes warning C6386 (Visual Studio bug)
								ctx.parentals[i]->users = NULL;
							} else {
								ctx.parentals[i]->users = (WCHAR**)malloc(users_array_length * sizeof(WCHAR*));
								if (ctx.parentals[i]->users) {
									for (int k = 0; k < users_array_length; k++) {
										ctx.parentals[i]->users[k] = (WCHAR*)malloc(sizeof(WCHAR) * ((array_value->u.object.values[j].value->u.array.values[k]->u.string.length) + 1));
										if (ctx.parentals[i]->users[k]) {
											mbstowcs(ctx.parentals[i]->users[k], array_value->u.object.values[j].value->u.array.values[k]->u.string.ptr, SIZE_MAX);
										} // else --> The pointer is null because it was not possible to allocate memory
									}
								} // else --> The pointer is null because it was not possible to allocate memory
							}
						}

						else if (strcmp(array_value->u.object.values[j].name, "ChallengeEqGroups") == 0) {
							groups_array_length = array_value->u.object.values[j].value->u.array.length;
							if (groups_array_length <= 0) {      // Fixes warning C6386 (Visual Studio bug)
								ctx.parentals[i]->challenge_groups = NULL;
							} else {
								// This will be a ChallengeEquivalenceGroup pointer pointer but for now it will hold ids, so force it to char pointer pointer
								#pragma warning(suppress: 4133)
								ctx.parentals[i]->challenge_groups = (char**)malloc(groups_array_length * sizeof(char*));
								if (ctx.parentals[i]->challenge_groups) {
									for (int k = 0; k < groups_array_length; k++) {
										// This will be a ChallengeEquivalenceGroup pointer but for now it will hold is, so force it to char pointer
										#pragma warning(suppress: 4133)
										ctx.parentals[i]->challenge_groups[k] = (char*)malloc(sizeof(char) * ((array_value->u.object.values[j].value->u.array.values[k]->u.string.length) + 1));
										if (ctx.parentals[i]->challenge_groups[k]) {
											#pragma warning(suppress: 4133)
											strcpy(ctx.parentals[i]->challenge_groups[k], array_value->u.object.values[j].value->u.array.values[k]->u.string.ptr);
										} // else --> The pointer is null because it was not possible to allocate memory
									}
								} // else --> The pointer is null because it was not possible to allocate memory
							}
						}
					}
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}

	PRINT(" - processParentalControls() ends\n");
}

static void processSyncFolders(json_value* value, int depth) {
	PRINT(" - processSyncFolders() starts\n");
	int array_length;
	array_length = value->u.array.length;
	if (array_length <= 0) {      // Fixes warning C6386 (Visual Studio bug)
		ctx.sync_folders = NULL;
	} else {
		ctx.sync_folders = (WCHAR**)malloc(array_length * sizeof(WCHAR*));
		if (ctx.sync_folders) 	{
			for (int i = 0; i < array_length; i++) {
				ctx.sync_folders[i] = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.array.values[i]->u.string.length) + 1));
				if (ctx.sync_folders[i]) {
					mbstowcs(ctx.sync_folders[i], value->u.array.values[i]->u.string.ptr, SIZE_MAX);
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processSyncFolders() ends\n");
}

static void processTableTuple(int table_index, int row_index, json_value* value, int depth) {
	int num_elems, x;
	enum AppType app_type = ANY;
	char* app_type_str;
	char* op_str;
	enum Operation op = NOTHING;

	num_elems = value->u.object.length;

	ctx.tables[table_index]->tuples[row_index] = (struct Tuple*)malloc(sizeof(struct Tuple));
	if (ctx.tables[table_index]->tuples[row_index]) {
		for (x = 0; x < num_elems; x++) {
			if (strcmp(value->u.object.values[x].name, "AppType") == 0) {
				app_type_str = value->u.object.values[x].value->u.string.ptr;
				if (strcmp(app_type_str, "BROWSER") == 0) app_type = BROWSER;
				else if (strcmp(app_type_str, "MAILER") == 0) app_type = MAILER;
				else if (strcmp(app_type_str, "BLOCKED") == 0) app_type = BLOCKED;
				else if (strcmp(app_type_str, "ANY") == 0) app_type = ANY;
				else {
					fprintf(stderr, "WARNING: incorrect apptype, defaulting to ANY.\n");
					app_type = ANY;         // If string does not match, ANY is used by default
				}
				ctx.tables[table_index]->tuples[row_index]->app_type = app_type;
			}

			else if (strcmp(value->u.object.values[x].name, "READ") == 0) {
				op_str = value->u.object.values[x].value->u.string.ptr;
				if (strcmp(op_str, "NOTHING") == 0)         op = NOTHING;
				else if (strcmp(op_str, "CIPHER") == 0)     op = CIPHER;
				else if (strcmp(op_str, "DECIPHER") == 0)   op = DECIPHER;
				else if (strcmp(op_str, "MARK") == 0)       op = MARK;
				else if (strcmp(op_str, "UNMARK") == 0)     op = UNMARK;
				else if (strcmp(op_str, "IF_MARK_UNMARK_ELSE_CIPHER") == 0)             op = IF_MARK_UNMARK_ELSE_CIPHER;
				else if (strcmp(op_str, "IF_MARK_UNMARK_DECHIPHER_ELSE_NOTHING") == 0)  op = IF_MARK_UNMARK_DECHIPHER_ELSE_NOTHING;
				else {
					fprintf(stderr, "WARNING: incorrect read operation, defaulting to NOTHING.\n");
					op = NOTHING;          // If string does not match, NOTHING is used by default
				}
				ctx.tables[table_index]->tuples[row_index]->on_read = op;
			}

			else if (strcmp(value->u.object.values[x].name, "WRITE") == 0) {
				op_str = value->u.object.values[x].value->u.string.ptr;
				if (strcmp(op_str, "NOTHING") == 0)         op = NOTHING;
				else if (strcmp(op_str, "CIPHER") == 0)     op = CIPHER;
				else if (strcmp(op_str, "DECIPHER") == 0)   op = DECIPHER;
				else if (strcmp(op_str, "MARK") == 0)       op = MARK;
				else if (strcmp(op_str, "UNMARK") == 0)     op = UNMARK;
				else if (strcmp(op_str, "IF_MARK_UNMARK_ELSE_CIPHER") == 0)             op = IF_MARK_UNMARK_ELSE_CIPHER;
				else if (strcmp(op_str, "IF_MARK_UNMARK_DECHIPHER_ELSE_NOTHING") == 0)  op = IF_MARK_UNMARK_DECHIPHER_ELSE_NOTHING;
				else {
					fprintf(stderr, "WARNING: incorrect write operation, defaulting to NOTHING.\n");
					op = NOTHING;          // If string does not match, NOTHING is used by default
				}
				ctx.tables[table_index]->tuples[row_index]->on_write = op;
			}
		}
	} // else --> The pointer is null because it was not possible to allocate memory
}

static void processOperativeTables(json_value* value, int depth) {
	PRINT(" - processOperativeTables() starts\n");
	int num_tables, i, j, num_rows;
	char* id_table;
	json_value* row_value;

	num_tables = value->u.object.length;
	if (num_tables <= 0) {      // Fixes warning C6386 (Visual Studio bug)
		ctx.tables = NULL;
	} else {
		ctx.tables = (struct OpTable**)malloc(num_tables * sizeof(struct OpTable*));
		if (ctx.tables) {
			for (i = 0; i < num_tables; i++) {
				id_table = value->u.object.values[i].name;
				ctx.tables[i] = (struct OpTable*)malloc(sizeof(struct OpTable));
				if (ctx.tables[i]) {
					ctx.tables[i]->id = (char*)malloc(sizeof(char) * ((value->u.object.values[i].name_length) + 1));
					if (ctx.tables[i]->id) {
						strcpy(ctx.tables[i]->id, id_table);

						// Each Tuple is a row of the Table (the number of tuples is the number of rows)
						num_rows = value->u.object.values[i].value->u.array.length;
						if (num_rows <= 0) {      // Fixes warning C6386 (Visual Studio bug)
							ctx.tables[i]->tuples = NULL;
						} else {
							ctx.tables[i]->tuples = (struct Tuple**)malloc(num_rows * sizeof(struct Tuple*));
							if (ctx.tables[i]->tuples) {
								for (j = 0; j < num_rows; j++) {
									row_value = value->u.object.values[i].value->u.array.values[j];
									processTableTuple(i, j, row_value, depth + 1);
								}
							} // else --> The pointer is null because it was not possible to allocate memory
						}
					} // else --> The pointer is null because it was not possible to allocate memory
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processOperativeTables() ends\n");
}

static void processApp(int index, json_value* value, int depth) {
	int num_elem, i;
	char* app_type_str = "";
	enum AppType type = ANY;

	// Cada app es un diccionario, una tupla con nombre de tres elementos
	ctx.apps[index] = (struct App*)malloc(sizeof(struct App));
	if (ctx.apps[index]) {
		num_elem = value->u.object.length;
		for (i = 0; i < num_elem; i++) {
			if (strcmp(value->u.object.values[i].name, "AppPath") == 0) {
				ctx.apps[index]->path = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[i].value->u.string.length) + 1));
				if (ctx.apps[index]->path) {
					mbstowcs(ctx.apps[index]->path, value->u.object.values[i].value->u.string.ptr, SIZE_MAX);
				} // else --> The pointer is null because it was not possible to allocate memory
			}

			else if (strcmp(value->u.object.values[i].name, "AppName") == 0) {
				ctx.apps[index]->name = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[i].value->u.string.length) + 1));
				if (ctx.apps[index]->name) {
					mbstowcs(ctx.apps[index]->name, value->u.object.values[i].value->u.string.ptr, SIZE_MAX);
				} // else --> The pointer is null because it was not possible to allocate memory
			}

			else if (strcmp(value->u.object.values[i].name, "AppType") == 0) {
				app_type_str = value->u.object.values[i].value->u.string.ptr;
				if (strcmp(app_type_str, "BROWSER") == 0) type = BROWSER;
				else if (strcmp(app_type_str, "MAILER") == 0) type = MAILER;
				else if (strcmp(app_type_str, "BLOCKED") == 0) type = BLOCKED;
				else if (strcmp(app_type_str, "ANY") == 0) type = ANY;
				else {
					fprintf(stderr, "WARNING: incorrect apptype, defaulting to ANY.\n");
					type = ANY;         // If string does not match, ANY is used by default
				}
				ctx.apps[index]->type = type;
			}
		}
	} // else --> The pointer is null because it was not possible to allocate memory
}

static void processApps(json_value* value, int depth) {
	PRINT(" - processApps() starts\n");
	//Lista de diccionarios
	int i, num_apps;
	json_value* app_value;
	num_apps = value->u.array.length;

	if (num_apps <= 0) {      // Fixes warning C6386 (Visual Studio bug)
		ctx.apps = NULL;
	} else {
		ctx.apps = (struct App**)malloc(num_apps * sizeof(struct App*));
		if (ctx.apps) {
			for (i = 0; i < num_apps; i++) {
				app_value = value->u.array.values[i];
				processApp(i, app_value, depth + 1);
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processApps() ends\n");
}

static void processChallenge(int group_index, int challenge_index, json_value* value, int depth) {
	int i, num_fields;

	num_fields = value->u.object.length;
	ctx.groups[group_index]->challenges[challenge_index] = malloc(sizeof(struct Challenge));
	if (ctx.groups[group_index]->challenges[challenge_index]) {
		for (i = 0; i < num_fields; i++) {
			// NOTE: Description and Requirements fields are merely informative. They are not passed to the context in any form.

			if (strcmp(value->u.object.values[i].name, "FileName") == 0) {
				ctx.groups[group_index]->challenges[challenge_index]->file_name = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[i].value->u.string.length) + 1));
				if (ctx.groups[group_index]->challenges[challenge_index]->file_name) {
					mbstowcs(ctx.groups[group_index]->challenges[challenge_index]->file_name, value->u.object.values[i].value->u.string.ptr, SIZE_MAX);
					ctx.groups[group_index]->challenges[challenge_index]->lib_handle = LoadLibraryW(ctx.groups[group_index]->challenges[challenge_index]->file_name);
					if (ctx.groups[group_index]->challenges[challenge_index]->lib_handle == NULL) {
						fprintf(stderr, "ERROR: could not load library '%ws' (code: %d)\n", ctx.groups[group_index]->challenges[challenge_index]->file_name, GetLastError());
					}
				} // else --> The pointer is null because it was not possible to allocate memory
			}

			else if (strcmp(value->u.object.values[i].name, "Props") == 0) {
				ctx.groups[group_index]->challenges[challenge_index]->properties = (char*)malloc(sizeof(char) * ((value->u.object.values[i].value->u.string.length) + 1));
				if (ctx.groups[group_index]->challenges[challenge_index]->properties) {
					strcpy(ctx.groups[group_index]->challenges[challenge_index]->properties, value->u.object.values[i].value->u.string.ptr);
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		}
	}
}

static void processChallengeEqGroup(int index, json_value* value, int depth) {
	int i, j, num_elems;
	int num_challenges = 0;
	json_value* challenge_value;

	num_elems = value->u.object.length;
	for (i = 0; i < num_elems; i++) {
		if (strcmp(value->u.object.values[i].name, "ChallengeList") == 0) {
			num_challenges = value->u.object.values[i].value->u.array.length;
			if (num_challenges <= 0) {      // Fixes warning C6386 (Visual Studio bug)
				ctx.groups[index]->challenges = NULL;
			} else {
				ctx.groups[index]->challenges = (struct Challenge**)malloc(num_challenges * sizeof(struct Challenge*));
				if (ctx.groups[index]->challenges) {
					for (j = 0; j < num_challenges; j++) {
						challenge_value = value->u.object.values[i].value->u.array.values[j];
						processChallenge(index, j, challenge_value, depth + 1);
					}
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		}
	}

	// Allocate the key
	ctx.groups[index]->subkey = (struct KeyData*)malloc(sizeof(struct KeyData) * 1);
	struct KeyData *key = ctx.groups[index]->subkey;
	if (key) {
		key->size = 0;                                            // Obtain from config.json?
		key->data = (byte*)malloc(sizeof(byte) * key->size);      // Key data is allocated as many space as indicated by the size member of the struct
		key->expires = (time_t)0;                                 // Key expired in 1970
	} // else --> The pointer is null because it was not possible to allocate memory

}

static void processChallengeEqGroups(json_value* value, int depth) {
	PRINT(" - processChallengeEqGroups() starts\n");
	int i, num_groups;
	json_value* group_value;

	num_groups = value->u.object.length;
	if (num_groups <= 0) {      // Fixes warning C6386 (Visual Studio bug)
		ctx.groups = NULL;
	} else {
		ctx.groups = (struct ChallengeEquivalenceGroup**)malloc(num_groups * sizeof(struct ChallengeEquivalenceGroup*));
		if (ctx.groups) {
			for (i = 0; i < num_groups; i++) {
				ctx.groups[i] = malloc(sizeof(struct ChallengeEquivalenceGroup));
				if (ctx.groups[i]) {
					// The group id is processeed here because it is the name of dictionary, the rest is done inside processChallengeGroup()
					ctx.groups[i]->id = malloc(sizeof(char) * ((value->u.object.values[i].name_length) + 1));
					if (ctx.groups[i]->id) {
						strcpy(ctx.groups[i]->id, value->u.object.values[i].name);
						group_value = value->u.object.values[i].value;
						processChallengeEqGroup(i, group_value, depth + 1);
					} // else --> The pointer is null because it was not possible to allocate memory
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processChallengeEqGroups() ends\n");
}

static void processCipher(int index, json_value* value, int depth) {
	int i, num_elems;

	num_elems = value->u.object.length;
	for (i = 0; i < num_elems; i++) {

		if (strcmp(value->u.object.values[i].name, "FileName") == 0) {
			ctx.ciphers[index]->file_name = (WCHAR*)malloc(sizeof(WCHAR) * ((value->u.object.values[i].value->u.string.length) + 1));
			if (ctx.ciphers[index]->file_name) {
				mbstowcs(ctx.ciphers[index]->file_name, value->u.object.values[i].value->u.string.ptr, SIZE_MAX);
				ctx.ciphers[index]->lib_handle = LoadLibraryW(ctx.ciphers[index]->file_name);
				if (ctx.ciphers[index]->lib_handle == NULL) {
					fprintf(stderr, "ERROR: could not load library '%ws'\n", ctx.ciphers[index]->file_name);
				}
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[i].name, "BlockSize") == 0) {
			ctx.ciphers[index]->block_size = (int)value->u.object.values[i].value->u.integer;
		}

		else if (strcmp(value->u.object.values[i].name, "Custom") == 0) {
			ctx.ciphers[index]->custom = (char*)malloc(sizeof(char) * ((value->u.object.values[i].value->u.string.length) + 1));
			if (ctx.ciphers[index]->custom) {
				strcpy(ctx.ciphers[index]->custom, value->u.object.values[i].value->u.string.ptr);
			} // else --> The pointer is null because it was not possible to allocate memory
		}
	}
}

static void processCiphers(json_value* value, int depth) {
	PRINT(" - processCiphers() starts\n");
	int i, num_ciphers;
	json_value* cipher_value;

	num_ciphers = value->u.object.length;
	if (num_ciphers <= 0) {     // Fixes warning C6386 (Visual Studio bug)
		ctx.ciphers = NULL;
	} else {
		ctx.ciphers = (struct Cipher**)malloc(num_ciphers * sizeof(struct Cipher*));
		if (ctx.ciphers) {
			for (i = 0; i < num_ciphers; i++) {
				ctx.ciphers[i] = malloc(sizeof(struct Cipher));
				if (ctx.ciphers[i]) {
					// The cipher id is processeed here because it is the name of dictionary, the rest is done inside processCipher()
					ctx.ciphers[i]->id = malloc(sizeof(char) * ((value->u.object.values[i].name_length) + 1));
					if (ctx.ciphers[i]->id) {
						strcpy(ctx.ciphers[i]->id, value->u.object.values[i].name);
						cipher_value = value->u.object.values[i].value;
						processCipher(i, cipher_value, depth + 1);
					} // else --> The pointer is null because it was not possible to allocate memory
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processCiphers() ends\n");
}

static void processThirdParty(int index, json_value* value, int depth) {
	int i, num_elems;

	num_elems = value->u.object.length;
	for (i = 0; i < num_elems; i++) {

		if (strcmp(value->u.object.values[i].name, "Cipher") == 0) {
			#pragma warning(suppress: 4133)
			ctx.third_parties[index]->cipher = (char*)malloc(sizeof(char) * ((value->u.object.values[i].value->u.string.length) + 1));
			if (ctx.third_parties[index]->cipher) {
				#pragma warning(suppress: 4133)
				strcpy(ctx.third_parties[index]->cipher, value->u.object.values[i].value->u.string.ptr);
			} // else --> The pointer is null because it was not possible to allocate memory
		}

		else if (strcmp(value->u.object.values[i].name, "Key") == 0) {
			ctx.third_parties[index]->key = (char*)malloc(sizeof(char) * ((value->u.object.values[i].value->u.string.length) + 1));
			if (ctx.third_parties[index]->key) {
				strcpy(ctx.third_parties[index]->key, value->u.object.values[i].value->u.string.ptr);
			} // else --> The pointer is null because it was not possible to allocate memory
		}
	}
}

static void processThirdParties(json_value* value, int depth) {
	PRINT(" - processThirdParties() starts\n");

	int i, num_third_parties;
	json_value* third_party_value;

	num_third_parties = value->u.object.length;
	if (num_third_parties <= 0) {     // Fixes warning C6386 (Visual Studio bug)
		ctx.third_parties = NULL;
	} else {
		ctx.third_parties = (struct ThirdParty**)malloc(num_third_parties * sizeof(struct ThirdParty*));
		if (ctx.third_parties) {
			for (i = 0; i < num_third_parties; i++) {
				ctx.third_parties[i] = malloc(sizeof(struct ThirdParty));
				if (ctx.third_parties[i]) {
					// The third party id is processeed here because it is the name of dictionary, the rest is done inside processThirdParty()
					ctx.third_parties[i]->id = malloc(sizeof(char) * ((value->u.object.values[i].name_length) + 1));
					if (ctx.third_parties[i]->id) {
						strcpy(ctx.third_parties[i]->id, value->u.object.values[i].name);
						third_party_value = value->u.object.values[i].value;
						processThirdParty(i, third_party_value, depth + 1);
					} // else --> The pointer is null because it was not possible to allocate memory
				} // else --> The pointer is null because it was not possible to allocate memory
			}
		} // else --> The pointer is null because it was not possible to allocate memory
	}
	PRINT(" - processThirdParties() ends\n");
}


/**
* Processes the json_value given as parameter (interpreted as full contents of config.json) and fills the context
*
* @return
**/
static void processContext(json_value* value, int depth) {
	int num_main_fields;
	PRINT("\nProcessing config.json and filling context...\n");
	num_main_fields = value->u.object.length;
	for (int i = 0;i < num_main_fields;i++) {
		if      (strcmp(value->u.object.values[i].name, "Folders") == 0)            processFolders(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "Pendrive") == 0)           processPendrive(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "ParentalControl") == 0)    processParentalControls(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "SyncFolders") == 0)        processSyncFolders(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "OperativeTables") == 0)    processOperativeTables(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "Apps") == 0)               processApps(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "ChallengeEqGroups") == 0)  processChallengeEqGroups(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "Ciphers") == 0)            processCiphers(value->u.object.values[i].value, depth + 1);
		else if (strcmp(value->u.object.values[i].name, "ThirdParties") == 0)       processThirdParties(value->u.object.values[i].value, depth + 1);
		else fprintf(stderr, "WARINING: the field '%s' included in config.json is not registered and will not be processed.\n", value->u.object.values[i].name);
	}
	PRINT("Processing completed\n");
}

#pragma endregion



/**
* Loads, reads and processes the config.json filling the global ctx variable. 
* 
* @return
**/
void loadContext() {
	char* file_name;
	FILE* fp;
	struct stat file_status;
	int file_size;
	char* file_contents;
	json_char* json;
	json_value* value;

	// Set json path
	file_name = "../../config.json";

	// Check availability of file and get size
	if (stat(file_name, &file_status) != 0) {
		fprintf(stderr, "File %s not found\n", file_name);
		exit(1);
	}
	file_size = file_status.st_size;

	// Assign space for the file contents
	file_contents = (char*)malloc(file_status.st_size);
	if (file_contents == NULL) {
		fprintf(stderr, "Memory error: unable to allocate %d bytes\n", file_size);
		exit(1);
	}

	// Try to open file
	fp = fopen(file_name, "rb");    // Read is done y binary mode. Othrewise fread() does not return (fails)
	if (fp == NULL) {
		fprintf(stderr, "Unable to open %s\n", file_name);
		//fclose(fp);       // It is not needed to close file if fopen() fails
		free(file_contents);
		exit(1);
	}
	if (fread(file_contents, file_size, 1, fp) != 1) {
		fprintf(stderr, "Unable t read content of %s\n", file_name);
		fprintf(stderr, "size %d\n", file_size);
		fclose(fp);
		free(file_contents);
		exit(1);
	}
	fclose(fp);

	// JSON parsing and syntax validation
	json = (json_char*)file_contents;
	value = json_parse(json, file_size);
	if (value == NULL) {
		fprintf(stderr, "Unable to parse data\n");
		free(file_contents);
		exit(1);
	}

	// Fill the context with all the JSON data
	processContext(value, 0);

	// Free unnecessary pointers
	json_value_free(value);     // This frees all the internal pointers. Be sure to have copied the data and not just pointed to it.
	free(file_contents);

	// Translate strings ids to pointers
	translateIdsToPointers();

	// Format all paths in the context
	formatCtxPaths();

	// Convert sync folder paths to use secure-mirror letters
	//convertSyncFolderPaths();

	// Convert parental paths to use secure-mirror letters
	//convertParentalFolderPaths();	// TO DO

	return;
}

/**
* Translates the char pointers which hold identifiers refering to other structs into pointers to those corresponding structs. 
* Frees the identifier pointers so there is no memory leak. 
* More specifically modifies the following fields: 
*   (Folders[i]->Protection->OpTable & ChallengeEqGroups & Cipher),
*   (Pendrive->Protection->OpTable & ChallengeEqGroups & Cipher),
*   (Parental Control->ChallengeEqGroups),
*   (Third Parties->Cipher).
* 
* @return
**/
void translateIdsToPointers() {
	void* tmp_ptr;

	PRINT("\nTranslating ids to pointers where possible...\n");

	//PRINT("Translating ids to pointers: Folders  -->  Protection\n");
	for (int i = 0; i < _msize(ctx.folders) / sizeof(struct Folder*); i++) {

		// Fix ids from:    Folders  -->  Protection  -->  OpTable
		//PRINT1("Translating ids to pointers: Folders  -->  Protection  -->  OpTable\n");

		//PRINT1("ID before changes: %s\n", (char*)ctx.folders[i]->protection->op_table);
		tmp_ptr = getOpTableById((char*)ctx.folders[i]->protection->op_table);  // Get true pointer
		free(ctx.folders[i]->protection->op_table);                             // Free the char* of the ID
		ctx.folders[i]->protection->op_table = tmp_ptr;                         // Assign the true pointer
		//PRINT1("ID after changes: %s\n", ctx.folders[i]->protection->op_table->id);

		// Fix ids from:    Folders  -->  Protection  -->  ChallengeEqGroups
		//PRINT1("Translating ids to pointers: Folders  -->  Protection  -->  ChallengeEqGroups: \n");
		for (int j = 0; j < _msize(ctx.folders[i]->protection->challenge_groups) / sizeof(char*); j++) {

			//PRINT2("ID before changes: %s\n", (char*)ctx.folders[i]->protection->challenge_groups[j]);
			tmp_ptr = getChallengeGroupById((char*)ctx.folders[i]->protection->challenge_groups[j]);    // Get true pointer
			free(ctx.folders[i]->protection->challenge_groups[j]);                                      // Free the char* of the ID
			ctx.folders[i]->protection->challenge_groups[j] = tmp_ptr;                                  // Assign the true pointer
			//PRINT2("ID after changes: %s\n", ctx.folders[i]->protection->challenge_groups[j]->id);
		}

		// Fix ids from:    Folders  -->  Protection  -->  Cipher
		//PRINT1("Translating ids to pointers: Folders  -->  Protection  -->  Cipher\n");

		//PRINT1("ID before changes: %s\n", (char*)ctx.folders[i]->protection->cipher);
		tmp_ptr = getCipherById((char*)ctx.folders[i]->protection->cipher);     // Get true pointer
		free(ctx.folders[i]->protection->cipher);                               // Free the char* of the ID
		ctx.folders[i]->protection->cipher = tmp_ptr;                           // Assign the true pointer
		//PRINT1("ID after changes: %s\n", ctx.folders[i]->protection->cipher->id);


	}


	//PRINT("Translating ids to pointers: Pendrive  -->  Protection\n");

	// Fix ids from:    Pendrive  -->  Protection  -->  OpTable
	//PRINT1("Translating ids to pointers: Pendrive  -->  Protection  -->  OpTable\n");

	//PRINT1("ID before changes: %s\n", (char*)ctx.pendrive->protection->op_table);
	tmp_ptr = getOpTableById((char*)ctx.pendrive->protection->op_table);        // Get true pointer
	free(ctx.pendrive->protection->op_table);                                   // Free the char* of the ID
	ctx.pendrive->protection->op_table = tmp_ptr;                               // Assign the true pointer
	//PRINT1("ID after changes: %s\n", ctx.pendrive->protection->op_table->id);

	// Fix ids from:    Pendrive  -->  Protection  -->  ChallengeEqGroups
	//PRINT1("Translating ids to pointers: Pendrive  -->  Protection  -->  ChallengeEqGroups: \n");
	for (int j = 0; j < _msize(ctx.pendrive->protection->challenge_groups) / sizeof(char*); j++) {

		//PRINT2("ID before changes: %s\n", (char*)ctx.pendrive->protection->challenge_groups[j]);
		tmp_ptr = getChallengeGroupById((char*)ctx.pendrive->protection->challenge_groups[j]);          // Get true pointer
		free(ctx.pendrive->protection->challenge_groups[j]);                                            // Free the char* of the ID
		ctx.pendrive->protection->challenge_groups[j] = tmp_ptr;                                        // Assign the true pointer
		//PRINT2("ID after changes: %s\n", ctx.pendrive->protection->challenge_groups[j]->id);
	}

	// Fix ids from:    Pendrive  -->  Protection  -->  Cipher
	//PRINT1("Translating ids to pointers: Pendrive  -->  Protection  -->  Cipher\n");

	//PRINT1("ID before changes: %s\n", (char*)ctx.pendrive->protection->cipher);
	tmp_ptr = getCipherById((char*)ctx.pendrive->protection->cipher);           // Get true pointer
	free(ctx.pendrive->protection->cipher);                                     // Free the char* of the ID
	ctx.pendrive->protection->cipher = tmp_ptr;                                 // Assign the true pointer
	//PRINT1("ID after changes: %s\n", ctx.pendrive->protection->cipher->id);


	// Fix ids from:    Parental Control  -->  ChallengeEqGroups
	//PRINT("Translating ids to pointers: Parental Control  -->  ChallengeEqGroups: \n");
	for (int i = 0; i < _msize(ctx.parentals) / sizeof(struct ParentalControl*); i++) {
		for (int j = 0; j < _msize(ctx.parentals[i]->challenge_groups) / sizeof(char*); j++) {

			//PRINT1("ID before changes: %s\n", (char*)ctx.parentals[i]->challenge_groups[j]);
			tmp_ptr = getChallengeGroupById((char*)ctx.parentals[i]->challenge_groups[j]);  // Get true pointer
			free(ctx.parentals[i]->challenge_groups[j]);                                    // Free the char* of the ID
			ctx.parentals[i]->challenge_groups[j] = tmp_ptr;                                // Assign the true pointer
			//PRINT1("ID after changes: %s\n", ctx.parentals[i]->challenge_groups[j]->id);
		}
	}


	// Fix ids from:    Third Parties  -->  Cipher
	//PRINT("Translating ids to pointers: Parental Control  -->  ChallengeEqGroups: \n");
	for (int i = 0; i < _msize(ctx.third_parties) / sizeof(struct ThirdParty*); i++) {
		//PRINT1("ID before changes: %s\n", (char*)ctx.third_parties[i]->cipher);
		tmp_ptr = getCipherById((char*)ctx.third_parties[i]->cipher);           // Get true pointer
		free(ctx.third_parties[i]->cipher);                                     // Free the char* of the ID
		ctx.third_parties[i]->cipher = tmp_ptr;                                 // Assign the true pointer
		//PRINT1("ID after changes: %s\n", ctx.third_parties[i]->cipher->id);
	}


	PRINT("Translation completed\n");
}

/**
* Goes though all the paths in the context and modifies them so all of them end with the same format ("X:/folder/file.ext").
* If there is no memory to perform the conversion, the context is not modified
*
* @return
**/
void formatCtxPaths() {
	PRINT("\nFormatting paths...\n");

	// Format mirrored folder paths
	for (int i = 0; i < _msize(ctx.folders) / sizeof(struct Folder*); i++) {
		formatPath(&ctx.folders[i]->path);
	}

	// Format parental paths
	for (int i = 0; i < _msize(ctx.parentals) / sizeof(struct ParentalControl*); i++) {
		formatPath(&ctx.parentals[i]->folder);
	}

	// Format sync folder paths
	for (int i = 0; i < _msize(ctx.sync_folders) / sizeof(WCHAR*); i++) {
		formatPath(&ctx.sync_folders[i]);
	}

	// Format application paths
	for (int i = 0; i < _msize(ctx.apps) / sizeof(struct App*); i++) {
		formatPath(&ctx.apps[i]->path);
	}

	PRINT("Formatting completed\n");
}

/**
* Converts the synchronized folder paths from the context so that they make use of the drive letters assigned to the mirrored drives.
* If there is no memory to perform the conversion, the context is not modified
*
* @return
**/
void convertSyncFolderPaths() {
	// In order to allow an N to N relation between sync folders and mirrored folders, it is necessary not to stop processing after a match is found.
	// If any sync folder does not affect any mirrored folder, it is removed.
	// Let S be the number of sync folders and M the number of mirrored folders, the final number of converted sync folders is in the range [0, S*M].

	// CASE 1:
	// Example syncfolder:      "C:\Users\Sergio\OneDrive\"
	// Example mirror path:     "C:\Users\Sergio\",  letter: 'H'
	// Result: syncfolder has to be changed to      "H:\OneDrive\"

	// CASE 2:
	// Example syncfolder:      "C:\Users\Sergio\OneDrive\"
	// Example mirror path:     "C:\Users\Sergio\Onedrive\",  letter: 'H'
	// Result: syncfolder has to be changed to      "H:\"

	// CASE 3:
	// Example syncfolder:      "C:\Users\Sergio\OneDrive\"
	// Example mirror path:     "C:\Users\Sergio\Onedrive\cosas\",  letter: 'H'
	// Result: syncfolder has to be change to       "H:\"

	// Any other case is a combination of the previous cases. Take next case as example
	// Example syncfolder:      "C:\Users\Sergio\OneDrive\"
	// Example mirror path:     "C:\Users\Sergio\",  letter: 'H'
	// Example mirror path:     "C:\Users\Sergio\Onedrive\cosas\",  letter: 'I'
	// Result: combination of case 1 and case 3. New sync folders: "H:\OneDrive\", "I:\"

	// Another example:
	// Example syncfolder:      "C:\Users\Sergio\Cosas\OneDrive\"
	// Example mirror path:     "C:\Users\Sergio\",  letter: 'H'
	// Example mirror path:     "C:\Users\Sergio\Cosas\",  letter: 'I'
	// Result: combination of case 1 and case 1 again. New sync folders: "H:\Cosas\OneDrive\", "I:\OneDrive\"

	WCHAR* tmp_str = NULL;
	size_t mirr_len = 0;
	size_t sync_len = 0;
	WCHAR** new_sync_folders = NULL;
	WCHAR** tmp_reallocated_new_sync_folders = NULL;
	int size_new_sync_folders = 10;
	int new_sync_folder_index = 0;

	PRINT("\nConverting sync folder paths to use secure-mirror letters where possible...\n");

	if (ctx.sync_folders == NULL) {
		return;
	}

	new_sync_folders = malloc(sizeof(WCHAR*) * size_new_sync_folders);
	if (new_sync_folders == NULL) {
		fprintf(stderr, "Error: not enough memory. Could not complete conversion.\n");
		return;
	}

	for (int i = 0; i < _msize(ctx.sync_folders) / sizeof(WCHAR*); i++) {
		// Each folder is: ctx.sync_folders[i]
		PRINT1("i: %d \t %ws\n", i, ctx.sync_folders[i]);

		// Check if for each of the Folders the path is prefix substring of the current syncfolder or vice versa
		for (int j = 0; j < _msize(ctx.folders) / sizeof(struct Folder*); j++) {
			// Each folder is: ctx.folders[j]->path
			PRINT2("j: %d \t\t %ws\n", j, ctx.folders[j]->path);

			mirr_len = wcslen(ctx.folders[j]->path);
			sync_len = wcslen(ctx.sync_folders[i]);
			if (mirr_len <= sync_len) {     // Only if mirror folder path is smaller or equal to sync folder path in length
				// CASE 1 or CASE 2
				tmp_str = wcsstr(ctx.sync_folders[i], ctx.folders[j]->path);
				if (tmp_str != NULL && tmp_str == ctx.sync_folders[i]) {
					// It matches a syncfolder (folder path is prefix of sync folder)
					PRINT3("Match found, case 1 or case 2. Processing...\n");

					tmp_str = (WCHAR*)malloc(sizeof(WCHAR) * (sync_len - mirr_len + 3 + 1));  // +3 to add letter ("X:\") and +1 is to add '\0'
					if (tmp_str != NULL) {
						tmp_str[0] = ctx.folders[j]->mount_point;
						tmp_str[1] = L':';
						tmp_str[2] = L'\\';
						wcscpy(&(tmp_str[3]), &((ctx.sync_folders[i])[mirr_len + 1]));  // Append the rest of sync folder and '\0' (+1 to skip slash)

						// Check if this match fits inside allocated space of new_sync_folders (if not, realloc so it fits)
						if (new_sync_folder_index >= size_new_sync_folders) {
							tmp_reallocated_new_sync_folders = realloc(new_sync_folders, size_new_sync_folders + 10);
							free(new_sync_folders);
							if (tmp_reallocated_new_sync_folders == NULL) {
								fprintf(stderr, "Error: not enough memory. Could not complete conversion.\n");
								return;
							}
							new_sync_folders = tmp_reallocated_new_sync_folders;
							tmp_reallocated_new_sync_folders = NULL;
						}
						// Copy the pointer and increment the index
						new_sync_folders[new_sync_folder_index] = tmp_str;
						tmp_str = NULL;
						new_sync_folder_index++;
					}
				}
			} else {
				// CASE 3
				tmp_str = wcsstr(ctx.folders[j]->path, ctx.sync_folders[i]);
				if (tmp_str != NULL && tmp_str == ctx.folders[j]->path) {
					// It matches a syncfolder (folder path is prefix of sync folder)
					PRINT3("Match found, case 3. Processing...\n");

					tmp_str = (WCHAR*)malloc(sizeof(WCHAR) * (3 + 1));  // 3 to add letter ("X:\") and +1 is to add '\0'
					if (tmp_str != NULL) {
						tmp_str[0] = ctx.folders[j]->mount_point;
						tmp_str[1] = L':';
						tmp_str[2] = L'\\';
						tmp_str[3] = L'\0';
					}

					// Check if this match fits inside allocated space of new_sync_folders (if not, realloc so it fits)
					if (new_sync_folder_index >= size_new_sync_folders) {
						tmp_reallocated_new_sync_folders = realloc(new_sync_folders, size_new_sync_folders + 10);
						free(new_sync_folders);
						if (tmp_reallocated_new_sync_folders == NULL) {
							fprintf(stderr, "Error: not enough memory. Could not complete conversion.\n");
							return;
						}
						new_sync_folders = tmp_reallocated_new_sync_folders;
						tmp_reallocated_new_sync_folders = NULL;
					}
					// Copy the pointer and increment the index
					new_sync_folders[new_sync_folder_index] = tmp_str;
					tmp_str = NULL;
					new_sync_folder_index++;
				}
			}
		}
	}
	// At this point:
	// - ctx.sync_folders: has all old (non-translated) paths
	// - new_sync_folders: has all new (translated) paths up to new_sync_folder_index (after that is not initializd memory),
	//      but its size is size_new_sync_folders (>= new_sync_folder_index)

	PRINT1("Cleaning and reasigning internal pointers...\n");

	// Free all initial sync folders and the sync_folders pointer itself
	for (int i = 0; i < _msize(ctx.sync_folders) / sizeof(WCHAR*); i++) {
		free(ctx.sync_folders[i]);
	}
	free(ctx.sync_folders);


	// Try to allocate memory for the correct size in ctx.sync_folders:
	//      If it works: put the pointers to the translated paths in this new buffer and free the other (new_sync_folders)
	//      If it does not work: assign the pointer to new_sync_folders to ctx.sync_folders and fill with NULLs the non used space for pointers.
	ctx.sync_folders = malloc(sizeof(WCHAR*) * new_sync_folder_index);
	if (ctx.sync_folders) {
		for (int i = 0; i < new_sync_folder_index; i++) {
			ctx.sync_folders[i] = new_sync_folders[i];
		}
		free(new_sync_folders);
	} else {
		ctx.sync_folders = new_sync_folders;
		for (int i = new_sync_folder_index; i < size_new_sync_folders; i++) {
			ctx.sync_folders[i] = NULL;
		}
	}

	PRINT("Conversion completed\n");
}

/**
* Converts the parental folder paths from the context so that they make use of the drive letters assigned to the mirrored drives.
* If there is no memory to perform the conversion, the context is not modified.
*
* @return
**/
void convertParentalFolderPaths() {
	PRINT("TO DO convertParentalFolderPaths() \n");
}
