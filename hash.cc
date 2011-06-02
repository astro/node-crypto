#include <node.h>
#include <string.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "hash.h"

void Hash::Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", HashInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", HashUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "digest", HashDigest);

    target->Set(String::NewSymbol("Hash"), t->GetFunction());
  }

bool Hash::HashInit (const char* hashType)
  {
    md = EVP_get_digestbyname(hashType);
    if(!md) {
      fprintf(stderr, "node-crypto : Unknown message digest %s\n", hashType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

int Hash::HashUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_DigestUpdate(&mdctx, data, len);
    return 1;
  }

int Hash::HashDigest(unsigned char** md_value, unsigned int *md_len) {
    if (!initialised)
      return 0;
    *md_value = (unsigned char*) malloc(EVP_MAX_MD_SIZE);
    EVP_DigestFinal_ex(&mdctx, *md_value, md_len);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    return 1;
  }


Handle<Value>
Hash::New (const Arguments& args)
  {
    HandleScope scope;

    Hash *hash = new Hash();
    hash->Wrap(args.This());
    return args.This();
  }

Handle<Value>
Hash::HashInit(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give hashtype string as argument"));
    }

    String::Utf8Value hashType(args[0]->ToString());

    bool r = hash->HashInit(*hashType);

    return args.This();
  }

Handle<Value>
Hash::HashUpdate(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

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

    int r = hash->HashUpdate(buf, len);

    return args.This();
  }

Handle<Value>
Hash::HashDigest(const Arguments& args) {
    Hash *hash = ObjectWrap::Unwrap<Hash>(args.This());

    HandleScope scope;

    unsigned char* md_value;
    unsigned int md_len;
    char* md_hexdigest;
    int md_hex_len;
    Local<Value> outString ;

    int r = hash->HashDigest(&md_value, &md_len);

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
	fprintf(stderr, "node-crypto : Hash .digest encoding "
		"can be binary, hex or base64\n");
      }
    }
    free(md_value);
    return scope.Close(outString);

  }

Hash::Hash () : ObjectWrap () 
  {
    initialised = false;
  }

Hash::~Hash ()
  {
  }
