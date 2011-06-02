#include <string.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "cipher.h"

void Cipher::Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", CipherInit);
    NODE_SET_PROTOTYPE_METHOD(t, "initiv", CipherInitIv);
    NODE_SET_PROTOTYPE_METHOD(t, "update", CipherUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "final", CipherFinal);

    target->Set(String::NewSymbol("Cipher"), t->GetFunction());
  }

bool Cipher::CipherInit(char* cipherType, char* key_buf, int key_buf_len)
  {
    cipher = EVP_get_cipherbyname(cipherType);
    if(!cipher) {
      fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
      return false;
    }

    unsigned char key[EVP_MAX_KEY_LENGTH],iv[EVP_MAX_IV_LENGTH];
    int key_len = EVP_BytesToKey(cipher, EVP_md5(), NULL, (unsigned char*) key_buf, key_buf_len, 1, key, iv);

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit(&ctx,cipher,(unsigned char *)key,(unsigned char *)iv, true);
    if (!EVP_CIPHER_CTX_set_key_length(&ctx,key_len)) {
    	fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    	EVP_CIPHER_CTX_cleanup(&ctx);
    	return false;
    }
    initialised = true;
    return true;
  }


bool Cipher::CipherInitIv(char* cipherType, char* key, int key_len, char *iv, int iv_len)
  {
    cipher = EVP_get_cipherbyname(cipherType);
    if(!cipher) {
      fprintf(stderr, "node-crypto : Unknown cipher %s\n", cipherType);
      return false;
    }
    if (EVP_CIPHER_iv_length(cipher)!=iv_len) {
    	fprintf(stderr, "node-crypto : Invalid IV length %d\n", iv_len);
      return false;
    }
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit(&ctx,cipher,(unsigned char *)key,(unsigned char *)iv, true);
    if (!EVP_CIPHER_CTX_set_key_length(&ctx,key_len)) {
    	fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
    	EVP_CIPHER_CTX_cleanup(&ctx);
    	return false;
    }
    initialised = true;
    return true;
  }


int Cipher::CipherUpdate(char* data, int len, unsigned char** out, int* out_len) {
    if (!initialised)
      return 0;
    *out_len=len+EVP_CIPHER_CTX_block_size(&ctx);
    *out=(unsigned char*)malloc(*out_len);
    
    EVP_CipherUpdate(&ctx, *out, out_len, (unsigned char*)data, len);
    return 1;
  }

int Cipher::CipherFinal(unsigned char** out, int *out_len) {
    if (!initialised)
      return 0;
    *out = (unsigned char*) malloc(EVP_CIPHER_CTX_block_size(&ctx));
    EVP_CipherFinal(&ctx,*out,out_len);
    EVP_CIPHER_CTX_cleanup(&ctx);
    initialised = false;
    return 1;
  }


Handle<Value>
Cipher::New (const Arguments& args)
  {
    HandleScope scope;

    Cipher *cipher = new Cipher();
    cipher->Wrap(args.This());
    return args.This();
  }

Handle<Value>
Cipher::CipherInit(const Arguments& args) {
    Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());
		
    HandleScope scope;

    cipher->incomplete_base64=NULL;

    if (args.Length() <= 1 || !args[0]->IsString() || !args[1]->IsString()) {
      return ThrowException(String::New("Must give cipher-type, key"));
    }
    

    ssize_t key_buf_len = DecodeBytes(args[1], BINARY);

    if (key_buf_len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    
    char* key_buf = new char[key_buf_len];
    ssize_t key_written = DecodeWrite(key_buf, key_buf_len, args[1], BINARY);
    assert(key_written == key_buf_len);
    
    String::Utf8Value cipherType(args[0]->ToString());

    bool r = cipher->CipherInit(*cipherType, key_buf, key_buf_len);

    return args.This();
  }

Handle<Value>
Cipher::CipherInitIv(const Arguments& args) {
    Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());
		
    HandleScope scope;

    cipher->incomplete_base64=NULL;

    if (args.Length() <= 2 || !args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
      return ThrowException(String::New("Must give cipher-type, key, and iv as argument"));
    }
    ssize_t key_len = DecodeBytes(args[1], BINARY);

    if (key_len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    
    ssize_t iv_len = DecodeBytes(args[2], BINARY);

    if (iv_len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* key_buf = new char[key_len];
    ssize_t key_written = DecodeWrite(key_buf, key_len, args[1], BINARY);
    assert(key_written == key_len);
    
    char* iv_buf = new char[iv_len];
    ssize_t iv_written = DecodeWrite(iv_buf, iv_len, args[2], BINARY);
    assert(iv_written == iv_len);

    String::Utf8Value cipherType(args[0]->ToString());
    	
    bool r = cipher->CipherInitIv(*cipherType, key_buf,key_len,iv_buf,iv_len);

    return args.This();
  }


Handle<Value>
Cipher::CipherUpdate(const Arguments& args) {
    Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());

    HandleScope scope;

    enum encoding enc = ParseEncoding(args[1]);
    ssize_t len = DecodeBytes(args[0], enc);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], enc);
    assert(written == len);

    unsigned char *out=0;
    int out_len=0;
    int r = cipher->CipherUpdate(buf, len,&out,&out_len);
    
    Local<Value> outString;
    if (out_len==0) outString=String::New("");
    else {
    	if (args.Length() <= 2 || !args[2]->IsString()) {
	      // Binary
	      outString = Encode(out, out_len, BINARY);
	    } else {
	      char* out_hexdigest;
	      int out_hex_len;
	      String::Utf8Value encoding(args[2]->ToString());
	      if (strcasecmp(*encoding, "hex") == 0) {
	        // Hex encoding
	        hex_encode(out, out_len, &out_hexdigest, &out_hex_len);
	        outString = Encode(out_hexdigest, out_hex_len, BINARY);
	        free(out_hexdigest);
	      } else if (strcasecmp(*encoding, "base64") == 0) {
		// Base64 encoding
		// Check to see if we need to add in previous base64 overhang
		if (cipher->incomplete_base64!=NULL){
		  unsigned char* complete_base64 = (unsigned char *)malloc(out_len+cipher->incomplete_base64_len+1);
		  memcpy(complete_base64, cipher->incomplete_base64, cipher->incomplete_base64_len);
		  memcpy(&complete_base64[cipher->incomplete_base64_len], out, out_len);
		  free(out);
		  free(cipher->incomplete_base64);
		  cipher->incomplete_base64=NULL;
		  out=complete_base64;
		  out_len += cipher->incomplete_base64_len;
		}

		// Check to see if we need to trim base64 stream
		if (out_len%3!=0){
		  cipher->incomplete_base64_len = out_len%3;
		  cipher->incomplete_base64 = (char *)malloc(cipher->incomplete_base64_len+1);
		  memcpy(cipher->incomplete_base64, &out[out_len-cipher->incomplete_base64_len], cipher->incomplete_base64_len);
		  out_len -= cipher->incomplete_base64_len;
		  out[out_len]=0;
		}

	        base64(out, out_len, &out_hexdigest, &out_hex_len);
	        outString = Encode(out_hexdigest, out_hex_len, BINARY);
	        free(out_hexdigest);
	      } else if (strcasecmp(*encoding, "binary") == 0) {
	        outString = Encode(out, out_len, BINARY);
	      } else {
		fprintf(stderr, "node-crypto : Cipher .update encoding "
			"can be binary, hex or base64\n");
	      }
	    }
    }
    if (out) free(out);
    return scope.Close(outString);
  }

Handle<Value>
Cipher::CipherFinal(const Arguments& args) {
    Cipher *cipher = ObjectWrap::Unwrap<Cipher>(args.This());

    HandleScope scope;

    unsigned char* out_value;
    int out_len;
    char* out_hexdigest;
    int out_hex_len;
    Local<Value> outString ;

    int r = cipher->CipherFinal(&out_value, &out_len);

    if (out_len == 0 || r == 0) {
      return scope.Close(String::New(""));
    }

    if (args.Length() == 0 || !args[0]->IsString()) {
      // Binary
      outString = Encode(out_value, out_len, BINARY);
    } else {
      String::Utf8Value encoding(args[0]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_encode(out_value, out_len, &out_hexdigest, &out_hex_len);
        outString = Encode(out_hexdigest, out_hex_len, BINARY);
        free(out_hexdigest);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        base64(out_value, out_len, &out_hexdigest, &out_hex_len);
        outString = Encode(out_hexdigest, out_hex_len, BINARY);
        free(out_hexdigest);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(out_value, out_len, BINARY);
      } else {
	fprintf(stderr, "node-crypto : Cipher .final encoding "
		"can be binary, hex or base64\n");
      }
    }
    free(out_value);
    return scope.Close(outString);

  }

Cipher::Cipher () : ObjectWrap () 
  {
    initialised = false;
  }

Cipher::~Cipher ()
  {
  }
