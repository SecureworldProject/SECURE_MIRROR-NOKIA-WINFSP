/*
* SecureWorld file keymaker.c
* Contains the key making and obtaining functions, which check validity of the key and invoke the challenges using dlls if necessary.

Nokia mayo 2021
*/

/////  FILE INCLUDES  /////

#include "keymaker.h"




/////  FUNCTION PROTOTYPES  /////

struct KeyData* getSubkey(struct ChallengeEquivalenceGroup* challenge_group);




/////  FUNCTION DEFINITIONS  /////

/**
 * Updates the composed_key parameter with a time-valid full key depending on the given challenge groups.
 */
int makeComposedKey(struct ChallengeEquivalenceGroup** challenge_groups, struct KeyData* composed_key) {
	// TO DO (possible improvements)
	// Idea 1: may be better to limit the max number of keys and make it array.
	// Idea 2: remove keys local var and getSubkey() twice instead of saving the result.
	// Idea 3: remove keys local var and asume subkey sizes are fixed and already initialized. Get the size directly and then call getSubkey() once.

	struct KeyData** keys = NULL;
	int num_groups = 0;
	int index = 0;

	// Param checking
	if (composed_key == NULL)		return 1;	// One or more params are null
	if (challenge_groups == NULL)	return 2;	// There are no groups, cannot make a key

	num_groups = _msize(challenge_groups) / sizeof(struct ChallengeEquivalenceGroup*);
	if (num_groups <= 0)			return 2;	// There are no groups, cannot make a key

	// Allocate local variable keys to hold pointers to all subkeys
	keys = malloc(sizeof(struct KeyData*) * num_groups);		// Can be changed to array limmiting the maximum number of challenge groups
	if (keys == NULL)				return 3;	// Cannot allocate memory

	if (composed_key->data != NULL) {
		free(composed_key->data);
	}
	composed_key->size = 0;

	// Get composed key size and allocate corresponding memory in data member
	for (size_t i = 0; i < num_groups; i++) {
		keys[i] = getSubkey(challenge_groups[i]);
		composed_key->size += keys[i]->size;
	}
	composed_key->data = calloc(composed_key->size, sizeof(byte));
	if (composed_key->data == NULL)	return 3;	// Cannot allocate memory

	// Compose the key
	for (size_t i = 0; i < num_groups; i++) {
		memcpy(&(composed_key->data[index]), keys[i]->data, keys[i]->size);
		index += keys[i]->size;
	}

	// Free local variable keys
	free(keys);

	return 0;	// Success
}


/**
 Returns a time-valid subkey for the given challenge group. In case key expired, forces computation at the moment.
 */
struct KeyData* getSubkey(struct ChallengeEquivalenceGroup* challenge_group) {
	time_t current_time = 0;
	typedef int(__stdcall* exec_ch_func_type)();

	int result = 0;
	exec_ch_func_type exec_ch_func;


	// In fact, it is irrelevant if it cannot be obtained. It just forces compute key in that case
	/*if (time(&current_time) == -1) {
		fprintf(stderr, "Error while getting current time in getSubkey().\n");
	}*/

	// Get current time
	time(&current_time);

	// Check if key expired and needs to be computed now
	if (difftime(current_time, challenge_group->subkey->expires) < 0) {
		// Iterate over challenges until one returns that it could be executed
		for (size_t j = 0; j < _msize(challenge_group->challenges) / sizeof(struct Challenge*); j++) {
			// Define function pointer corresponding with executeChallenge() input and output types
			exec_ch_func = (exec_ch_func_type)GetProcAddress(challenge_group->challenges[j]->lib_handle, "executeChallenge");

			// Add parameters if necessary
			if (exec_ch_func != NULL) {
				result = exec_ch_func(challenge_group, challenge_group->challenges[j]);
				if (result != 0) {
					PRINT("WARNING: error trying to execute the challenge '%ws'\n", challenge_group->challenges[j]->file_name);
				} else {
					break;		// Stop executing more challenges in the group when one is already working
				}
			} else {
				PRINT("WARNING: error accessing the address to the executeChallenge() function of the challenge '%ws' (error: %d)\n", challenge_group->challenges[j]->file_name, GetLastError());
			}
		}
	}

	return challenge_group->subkey;
}


/**
  Updates the block_access variable depending on the given challenge groups.
 */
int makeParentalKey(struct ChallengeEquivalenceGroup** challenge_groups, BOOL *block_access) {
	int num_groups = 0;
	int index = 0;
	*block_access = FALSE;

	if (block_access == NULL)		return 1;	// block_access is NULL

	if (challenge_groups == NULL)	return 0;	// No challenge groups (same as if all challenges are passed)

	num_groups = _msize(challenge_groups) / sizeof(struct ChallengeEquivalenceGroup*);
	if (num_groups <= 0)			return 0;	// No challenge groups (same as if all challenges are passed)

	// Make the key
	for (size_t i = 0; i < num_groups; i++) {
		*block_access |= getSubkey(challenge_groups[i])->data[0];
	}

	return 0;	// Success
}