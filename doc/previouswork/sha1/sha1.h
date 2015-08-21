#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h> 

enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};

#define SHA1HashSize 20
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))


typedef struct SHA1Context
{
 uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest          */
 uint32_t Length_Low;               /* Message length in bits           */
 uint32_t Length_High;              /* Message length in bits           */
 int_least16_t Message_Block_Index; /* Index into message block array   */
 uint8_t Message_Block[64];         /* 512-bit message blocks           */
 int Computed;                      /* Is the digest computed?          */
 int Corrupted;                     /* Is the message digest corrupted? */
} SHA1Context;

int SHA1Reset(  SHA1Context *);
int SHA1Input(  SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result( SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);
void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

int SHA1Reset(SHA1Context *context) {
  if (!context) {
    return shaNull;
  }
  context->Length_Low             = 0;
  context->Length_High            = 0;
  context->Message_Block_Index    = 0;
  context->Intermediate_Hash[0]   = 0x67452301;  /* H0 */
  context->Intermediate_Hash[1]   = 0xEFCDAB89;  /* H1 */
  context->Intermediate_Hash[2]   = 0x98BADCFE;  /* H2 */
  context->Intermediate_Hash[3]   = 0x10325476;  /* H3 */
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;  /* H4 */
  context->Computed   = 0;
  context->Corrupted  = 0;
  return shaSuccess;
}

void SHA1PadMessage(SHA1Context *context) {
  if (context->Message_Block_Index > 55) {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 64) {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
    SHA1ProcessMessageBlock(context);
    while(context->Message_Block_Index < 56) {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  } else {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 56) {
     context->Message_Block[context->Message_Block_Index++] = 0;
    }
  }
  /* Store the message length as the last 8 octets */
  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >> 8;
  context->Message_Block[59] = context->Length_High;
  context->Message_Block[60] = context->Length_Low >> 24;
  context->Message_Block[61] = context->Length_Low >> 16;
  context->Message_Block[62] = context->Length_Low >> 8;
  context->Message_Block[63] = context->Length_Low;
  SHA1ProcessMessageBlock(context);
}

int SHA1Result( SHA1Context *context, uint8_t Message_Digest[SHA1HashSize]) {
  int i;
  if (!context || !Message_Digest) {
    return shaNull;
  }
  if (context->Corrupted) {
    return context->Corrupted;
  }
  if (!context->Computed) {
    SHA1PadMessage(context);
    for(i=0; i<64; ++i) {
      context->Message_Block[i] = 0; /* message may be sensitive, clear it */
    }
    context->Length_Low = 0;         /* and clear length */
    context->Length_High = 0;
    context->Computed = 1;
  }
  for(i = 0; i < SHA1HashSize; ++i) {
    Message_Digest[i] = 
      context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
  }
  return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *context) {
  const uint32_t K[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
                              /* Constants defined in SHA-1  */
  int t;                      /* Loop counter                */
  uint32_t temp;              /* Temporary word value        */
  uint32_t W[80];             /* Word sequence               */
  uint32_t A, B, C, D, E;     /* Word buffers                */
  for(t = 0; t < 16; t++) {
    W[t] = context->Message_Block[t * 4] << 24;
    W[t] |= context->Message_Block[t * 4 + 1] << 16;
    W[t] |= context->Message_Block[t * 4 + 2] << 8;
    W[t] |= context->Message_Block[t * 4 + 3];
  }
  for(t = 16; t < 80; t++) {
    W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }
  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  for(t = 0; t < 20; t++) {
    temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }
  for(t = 20; t < 40; t++) {
    temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }
  for(t = 40; t < 60; t++) {
    temp = SHA1CircularShift(5,A)+((B & C) | (B & D) | (C & D))+E+W[t]+K[2];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }
  for(t = 60; t < 80; t++) {
    temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }
  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Message_Block_Index = 0;
}

int SHA1Input(SHA1Context    *context,
              const uint8_t  *message_array,
              unsigned       length) {
  if (!length) {
    return shaSuccess;
  }
  if (!context || !message_array) {
    return shaNull;
  }
  if (context->Computed) {
    context->Corrupted = shaStateError;
    return shaStateError;
  }
  if (context->Corrupted) {
     return context->Corrupted;
  }
  while(length-- && !context->Corrupted) {
    context->Message_Block[context->Message_Block_Index++] =
                  (*message_array & 0xFF);
    context->Length_Low += 8;
    if (context->Length_Low == 0) {
      context->Length_High++;
      if (context->Length_High == 0) {
        context->Corrupted = 1;   /* Message is too long */
      }
    }
    if (context->Message_Block_Index == 64) {
      SHA1ProcessMessageBlock(context);
    }
    message_array++;
  }
  return shaSuccess;
}

 
int lengthOfU(unsigned char * str)
{
    int i = 0;

    while(*(str++)){
    	i++;
    	if(i == INT_MAX)
    	    return -1;
    }

    return i;
}



void callsha1(unsigned char *testarray, int Size, int flag) {
int tt=0;
for(tt=0;tt<Size;tt++) {

printf("%02X", testarray[tt]);
}  
printf("\n");



  


    errr = SHA1Input(&sha,
                    (const unsigned char *) testarray,
                    Size);


    errr = SHA1Result(&sha, Message_Digest);

      printf("\t");
      for(m = 0; m < 20 ; ++m) {
        printf("%02X ", Message_Digest[m]);
      }
      printf("\n");
    printf("One done!\n");
  
}

