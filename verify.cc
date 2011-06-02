#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "crypto.h"
#include "verify.h"

void
Verify::Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "init", VerifyInit);
    NODE_SET_PROTOTYPE_METHOD(t, "update", VerifyUpdate);
    NODE_SET_PROTOTYPE_METHOD(t, "verify", VerifyFinal);

    target->Set(String::NewSymbol("Verify"), t->GetFunction());
  }

bool Verify::VerifyInit (const char* verifyType)
  {
    md = EVP_get_digestbyname(verifyType);
    if(!md) {
      fprintf(stderr, "node-crypto : Unknown message digest %s\n", verifyType);
      return false;
    }
    EVP_MD_CTX_init(&mdctx);
    EVP_VerifyInit_ex(&mdctx, md, NULL);
    initialised = true;
    return true;
    
  }

int Verify::VerifyUpdate(char* data, int len) {
    if (!initialised)
      return 0;
    EVP_VerifyUpdate(&mdctx, data, len);
    return 1;
  }

int Verify::VerifyFinal(char* keyPem, int keyPemLen, unsigned char* sig, int siglen) {
    if (!initialised)
      return 0;

    BIO *bp = NULL;
    EVP_PKEY* pkey;
    X509 *        x509;

    bp = BIO_new(BIO_s_mem()); 
    if(!BIO_write(bp, keyPem, keyPemLen))
      return 0;

    x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL );
    if (x509==NULL)
      return 0;

    pkey=X509_get_pubkey(x509);
    if (pkey==NULL)
      return 0;

    int r = EVP_VerifyFinal(&mdctx, sig, siglen, pkey);
    EVP_PKEY_free (pkey);

    if (r != 1) {
      ERR_print_errors_fp (stderr);
    }
    X509_free(x509);
    BIO_free(bp);
    EVP_MD_CTX_cleanup(&mdctx);
    initialised = false;
    return r;
  }


Handle<Value>
Verify::New (const Arguments& args)
  {
    HandleScope scope;

    Verify *verify = new Verify();
    verify->Wrap(args.This());

    return args.This();
  }

Handle<Value>
Verify::VerifyInit(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

    HandleScope scope;

    if (args.Length() == 0 || !args[0]->IsString()) {
      return ThrowException(String::New("Must give verifytype string as argument"));
    }

    String::Utf8Value verifyType(args[0]->ToString());

    bool r = verify->VerifyInit(*verifyType);

    return args.This();
  }

Handle<Value>
Verify::VerifyUpdate(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

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

    int r = verify->VerifyUpdate(buf, len);

    return args.This();
  }

Handle<Value>
Verify::VerifyFinal(const Arguments& args) {
    Verify *verify = ObjectWrap::Unwrap<Verify>(args.This());

    HandleScope scope;

    ssize_t klen = DecodeBytes(args[0], BINARY);

    if (klen < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

    char* kbuf = new char[klen];
    ssize_t kwritten = DecodeWrite(kbuf, klen, args[0], BINARY);
    assert(kwritten == klen);


    ssize_t hlen = DecodeBytes(args[1], BINARY);

    if (hlen < 0) {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
    
    unsigned char* hbuf = new unsigned char[hlen];
    ssize_t hwritten = DecodeWrite((char *)hbuf, hlen, args[1], BINARY);
    assert(hwritten == hlen);
    unsigned char* dbuf;
    int dlen;

    int r=-1;

    if (args.Length() == 2 || !args[2]->IsString()) {
      // Binary
      r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
    } else {
      String::Utf8Value encoding(args[2]->ToString());
      if (strcasecmp(*encoding, "hex") == 0) {
        // Hex encoding
        hex_decode(hbuf, hlen, (char **)&dbuf, &dlen);
        r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
	free(dbuf);
      } else if (strcasecmp(*encoding, "base64") == 0) {
        // Base64 encoding
        unbase64(hbuf, hlen, (char **)&dbuf, &dlen);
        r = verify->VerifyFinal(kbuf, klen, dbuf, dlen);
	free(dbuf);
      } else if (strcasecmp(*encoding, "binary") == 0) {
        r = verify->VerifyFinal(kbuf, klen, hbuf, hlen);
      } else {
	fprintf(stderr, "node-crypto : Verify .verify encoding "
		"can be binary, hex or base64\n");
      }
    }

    return scope.Close(Integer::New(r));
  }

Verify::Verify () : ObjectWrap () 
  {
    initialised = false;
  }

Verify::~Verify ()
  {
  }
