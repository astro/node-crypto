#include <node.h>
#include <string.h>

#include "crypto.h"
#include "hmac.h"

using namespace v8;
using namespace node;


void
Hmac::Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", HmacInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", HmacUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "digest", HmacDigest);

    target->Set(String::NewSymbol("Hmac"), t->GetFunction());
  }

bool Hmac::HmacInit(char* hashType, char* key, int key_len)
  {
    md = EVP_get_digestbyname(hashType);
    if(!md) {
      fprintf(stderr, "node-crypto : Unknown message digest %s\n", hashType);
      return false;
    }
    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, key, key_len, md);
    initialised = true;
    return true;
    
  }

int Hmac::HmacUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    HMAC_Update(&ctx, (unsigned char*)data, len);
    return 1;
  }

int Hmac::HmacDigest(unsigned char** md_value, unsigned int *md_len) {
    if (!initialised)
      return 0;
    *md_value = (unsigned char*) malloc(EVP_MAX_MD_SIZE);
    HMAC_Final(&ctx, *md_value, md_len);
    HMAC_CTX_cleanup(&ctx);
    initialised = false;
    return 1;
  }

Handle<Value>
Hmac::New (const Arguments& args)
  {
    HandleScope scope;

    Hmac *hmac = new Hmac();
    hmac->Wrap(args.This());
    return args.This();
  }

Handle<Value>
Hmac::HmacInit(const Arguments& args) {
    Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give hashtype string as argument"));
    }

    ssize_t len = DecodeBytes(args[1], BINARY);

    if (len < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* buf = new char[len];
    ssize_t written = DecodeWrite(buf, len, args[1], BINARY);
    assert(written == len);

    String::Utf8Value hashType(args[0]->ToString());

    bool r = hmac->HmacInit(*hashType, buf, len);

    return args.This();
  }

Handle<Value>
Hmac::HmacUpdate(const Arguments& args) {
    Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

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

    int r = hmac->HmacUpdate(buf, len);

    return args.This();
  }

Handle<Value>
Hmac::HmacDigest(const Arguments& args) {
    Hmac *hmac = ObjectWrap::Unwrap<Hmac>(args.This());

    HandleScope scope;

    unsigned char* md_value;
    unsigned int md_len;
    char* md_hexdigest;
    int md_hex_len;
    Local<Value> outString ;

    int r = hmac->HmacDigest(&md_value, &md_len);

    if (md_len == 0 || r == 0) {
      return scope.Close(String::New(""));
    }

    if (args.Length() == 0 || !args[0]->IsString()) {
      // Binary
      outString = Encode(md_value, md_len, BINARY);
    } else {
      String::Utf8Value encoding(args[0]->ToString());
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
	fprintf(stderr, "node-crypto : Hmac .digest encoding "
		"can be binary, hex or base64\n");
      }
    }
    free(md_value);
    return scope.Close(outString);

  }

Hmac::Hmac () : ObjectWrap () 
  {
    initialised = false;
  }

Hmac::~Hmac ()
  {
  }

