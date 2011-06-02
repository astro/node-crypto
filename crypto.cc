#include <node.h>
#include <node_events.h>
#include <assert.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "crypto.h"
#include "cipher.h"
#include "decipher.h"
#include "hash.h"
#include "hmac.h"
#include "sign.h"
#include "verify.h"


#define EVP_F_EVP_DECRYPTFINAL 101

using namespace v8;
using namespace node;

extern "C" void
init (Handle<Object> target) 
{
  HandleScope scope;

  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();

  Cipher::Initialize(target);
  Decipher::Initialize(target);
  Hmac::Initialize(target);
  Hash::Initialize(target);
  Sign::Initialize(target);
  Verify::Initialize(target);
}

void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest, int* md_hex_len) {
  *md_hex_len = (2*(md_len));
  *md_hexdigest = (char *) malloc(*md_hex_len + 1);
  for(int i = 0; i < md_len; i++) {
    sprintf((char *)(*md_hexdigest + (i*2)), "%02x",  md_value[i]);
  }
}

#define hex2i(c) ((c) <= '9' ? ((c) - '0') : (c) <= 'Z' ? ((c) - 'A' + 10) : ((c) - 'a' + 10))
void hex_decode(unsigned char *input, int length, char** buf64, int* buf64_len) {
  *buf64_len = (length/2);
  *buf64 = (char*) malloc(length/2 + 1);
  char *b = *buf64;
  for(int i = 0; i < length-1; i+=2) {
    b[i/2]  = (hex2i(input[i])<<4) | (hex2i(input[i+1]));
  }
}

void base64(unsigned char *input, int length, char** buf64, int* buf64_len)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  *buf64_len = bptr->length;
  *buf64 = (char *)malloc(*buf64_len+1);
  memcpy(*buf64, bptr->data, bptr->length);
  char* b = *buf64;
  b[bptr->length] = 0;

  BIO_free_all(b64);

}

void *unbase64(unsigned char *input, int length, char** buffer, int* buffer_len)
{
  BIO *b64, *bmem;
  *buffer = (char *)malloc(length);
  memset(*buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  *buffer_len = BIO_read(bmem, *buffer, length);
  BIO_free_all(bmem);

}



