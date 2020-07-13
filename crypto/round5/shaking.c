//	Copyright (c) 2020, PQShield Ltd and Koninklijke Philips N.V.,
//      Markku-Juhani O. Saarinen <mjos@pqshield.com>

#include "shaking.h"

//	Importing, build upon:

#include <assert.h>
#include <string.h>

//	Local routines:

inline void keccak_absorb
	( Context context
	, const uint8_t *input, size_t inputLength
	, uint8_t pad Parameters )
{
	while ( inputLength >= RATE ) {
		KeccakF1600_StateXORBytes(context->state, input Params);
		KeccakF1600_StatePermute(context->state);
		inputLength -= RATE;
		input += RATE;
	}
	memcpy(context->remaining, input, inputLength);
	context->remaining[inputLength] = pad;

	inputLength += 1;
	memset(&context->remaining[inputLength], 0x00, RATE - inputLength);
	context->remaining[RATE - 1] |= 0x80;
	KeccakF1600_StateXORBytes(context->state, context->remaining Params );
    
	context->index = &(context->remaining[RATE]);
}

// 	Exporting:

void r5_xof_input // init absorb finalize
	( Context context
	, const uint8_t *input, size_t inputLength Parameters )
{
	keccak_absorb(context, input, inputLength, 0x1F Params);
}

void r5_xof_squeeze
	( Context context
	, uint8_t *output, size_t outputLength Parameters )
{      
	uint8_t *buffer = context->index;
	size_t no = (size_t) ((&context->remaining[RATE]) - buffer);
	
	while( outputLength >= no ) {
		// memcpy( output, buffer, no );		
		while( buffer < &context->remaining[RATE] ) {
			*output++ = *buffer++; 
		}
		outputLength -= no;

		while( outputLength >= RATE ) {
			KeccakF1600_StatePermute(context->state);
            KeccakF1600_StateExtractBytes(context->state, output Params);
			outputLength -= RATE;
			output += RATE;
		}

		KeccakF1600_StatePermute(context->state);
        KeccakF1600_StateExtractBytes(context->state, context->remaining Params);
		no = RATE;
                buffer = context->remaining;
	}
	// memcpy( output, buffer, outputLength );	
	for ( size_t i = 0; i < outputLength; i++ ) {
	   *output++ = *buffer++;
	}
	context->index = buffer;
}

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#define address d=-d
#else
#define address 0
#endif

void r5_xof_squeeze16 
	( Context context
	, uint16_t *out, size_t outputLength Parameters )
{
	uint8_t *buffer = context->index;
	size_t no = (&context->remaining[RATE]) - buffer;
    
	uint8_t *output = ((uint8_t *) (out));
	outputLength *= 2;

	int d = -1;
	
	while( outputLength >= no ) {
		while( buffer < &context->remaining[RATE] ) {
			output[address] = *buffer++; 
			output++; 
		}
		outputLength -= no;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		while( outputLength >= RATE ) {
			KeccakF1600_StatePermute(context->state);
            KeccakF1600_StateExtractBytes(context->state, output Params);
			outputLength -= RATE;
			output += RATE;
		}
#endif
		KeccakF1600_StatePermute(context->state);
        KeccakF1600_StateExtractBytes(context->state, context->remaining Params);
		no = RATE;
                buffer = context->remaining;
	}
	for ( size_t i = 0; i < outputLength; i++ ) {
		output[address] = *buffer++; 
		output++; 
	}
	context->index = buffer;
}

void r5_xof // shake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters )
{
	ContextInstance context = {0}; 
	r5_xof_input(&context, input, inputLength Params); 
	r5_xof_squeeze(&context, output, outputLength Params);
}

void r5_xof16 // shake16
	( uint16_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters)
{
	ContextInstance context = {0};
	r5_xof_input(&context, input, inputLength Params );
	r5_xof_squeeze16(&context, output, outputLength Params);
}



void r5_xof_s_input // custom init absorb finalize
	( CContext context
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters ) 
{
    if (customizationLength == 0){
        keccak_absorb(context, input, inputLength, 0x1F Params);
    } else {
        uint8_t *in = context->remaining;
        *in++ = 0x01; *in++ = RATE; *in++ = 0x01;
        *in++ = 0x00; *in++ = 0x01;

        assert( customizationLength < 32 );

        *in++ = (uint8_t) (customizationLength << 3);
        memcpy(in, customization, customizationLength);

        KeccakF1600_StateXORBytes(context->state, context->remaining Params );
        KeccakF1600_StatePermute(context->state);

        keccak_absorb(context, input, inputLength, 0x04 Params );
    }
}


void r5_xof_s_squeeze // squeeze can't be reused since type of context differ
    ( CContext context
    , uint8_t *output, size_t outputLength Parameters )
{ r5_xof_squeeze(context, output, outputLength Params ); }

void r5_xof_s_squeeze16
    ( CContext context
    , uint16_t *output, size_t outputLength Parameters )
{ r5_xof_squeeze16(context, output, outputLength Params ); }

void r5_xof_s // cshake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters )
{
	ContextInstance context = {0};
	r5_xof_s_input(&context, input, inputLength, customization, customizationLength Params);
	r5_xof_squeeze(&context, output, outputLength Params );
}

void r5_xof_s16 // cshake16
	( uint16_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters )
{
	ContextInstance context = {0};
	r5_xof_s_input(&context, input, inputLength, customization, customizationLength Params );
	r5_xof_squeeze16(&context, output, outputLength Params );
}

