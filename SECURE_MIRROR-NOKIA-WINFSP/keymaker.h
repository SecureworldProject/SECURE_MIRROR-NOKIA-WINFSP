#ifndef KEYMAKER_H
#define KEYMAKER_H


/////  FILE INCLUDES  /////

#include "context.h"




/////  FUNCTION PROTOTYPES  /////

int makeComposedKey(struct ChallengeEquivalenceGroup** challenge_groups, struct KeyData* composed_key);

int makeParentalKey(struct ChallengeEquivalenceGroup** challenge_groups, BOOL* block_access);

#endif //!KEYMAKER_H
