/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#define PARAMETERCONSTANT

#define SHAKE128_RATE 168
// 168 bytes as a bytesequence = 1344 bits as a bitsequence

#define SHAKE256_RATE 136
// 136 bytes as a bytesequence = 1088 bits as a bitsequence

#ifdef PARAMETERCONSTANT

#include "r5_parameter_sets.h"

#define Parameters  
#define Params 
#define useParams 

#define RATE SHAKE128_RATE

#define DeclareParameters

#endif