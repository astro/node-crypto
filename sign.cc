#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypto.h"
#include "sign.h"

void Sign::Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", SignInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", SignUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "sign", SignFinal);

    target->Set(String::NewSymbol("Sign"), t->GetFunction());
  }

bool Sign::SignInit (const char* signType)
  {
    md = EVP_get_digestbyname(signType);
    if(!md) {
      printf("Unknown message digest %s\n", signType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_SignInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

  int Sign::SignUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_SignUpdate(&mdctx, data, len);
    return 1;
  }

  int Sign::SignFinal(unsigned char** md_value, unsigned int *md_len, char* keyPem, int keyPemLen) {
    if (!initialised)
      return 0;

    BIO *bp = NULL;
    EVP_PKEY* pkey;
    bp = BIO_new(BIO_s_mem()); 
    if(!BIO_write(bp, keyPem, keyPemLen))
      return 0;

    pkey = PEM_read_bio_PrivateKey( bp, NULL, NULL, NULL );
    if (pkey == NULL)
      return 0;

    EVP_SignFinal(&mdctx, *md_value, md_len, pkey);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    EVP_PKEY_free(pkey);
    BIO_free(bp);
    return 1;
  }


Handle<Value>
Sign::New (const Arguments& args)
  {
    HandleScope scope;

    Sign *sign = new Sign();
    sign->Wrap(args.This());

    return args.This();
  }

Handle<Value>
Sign::SignInit(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give signtype string as argument"));
    }

    String::Utf8Value signType(args[0]->ToString());

    bool r = sign->SignInit(*signType);

    return args.This();
  }

Handle<Value>
Sign::SignUpdate(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

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

    int r = sign->SignUpdate(buf, len);

    return args.This();
  }

Handle<Value>
Sign::SignFinal(const Arguments& args) {
    Sign *sign = ObjectWrap::Unwrap<Sign>(args.This());

    HandleScope scope;

    unsigned char* md_value;
    unsigned int md_len;
    char* md_hexdigest;
    int md_hex_len;
    Local<Value> outString;

    md_len = 8192; // Maximum key size is 8192 bits
    md_value = new unsigned char[md_len];

    ssize_t len = DecodeBytes(args[0], BINARY);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[0], BINARY);
    assert(written == len);


    int r = sign->SignFinal(&md_value, &md_len, buf, len);

    if (md_len == 0 || r == 0) {
      return scope.Close(String::New(""));
    }

    if (args.Length() == 1 || !args[1]->IsString()) {
      // Binary
      outString = Encode(md_value, md_len, BINARY);
    } else {
      String::Utf8Value encoding(args[1]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_encode(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        base64(md_value, md_len, &md_hexdigest, &md_hex_len);
        outString = Encode(md_hexdigest, md_hex_len, BINARY);
        free(md_hexdigest);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        outString = Encode(md_value, md_len, BINARY);
      } else {
	outString = String::New("");
	fprintf(stderr, "node-crypto : Sign .sign encoding "
		"can be binary, hex or base64\n");
      }
    }
    return scope.Close(outString);

  }

Sign::Sign () : ObjectWrap () 
  {
    initialised = false;
  }

Sign::~Sign ()
  {
  }
