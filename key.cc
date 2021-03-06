#include <node_buffer.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "key.h"

// http://sambro.is-super-awesome.com/2011/03/03/creating-a-proper-buffer-in-a-node-c-addon/
static Handle<Value> makeBuffer(unsigned char *data, int length) {
  HandleScope scope;

  Buffer *slowBuffer = Buffer::New(length);
  memcpy(Buffer::Data(slowBuffer), data, length);
  Local<Object> globalObj = Context::GetCurrent()->Global();
  Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
  Handle<Value> constructorArgs[3] = { slowBuffer->handle_, Integer::New(length), Integer::New(0) };
  Local<Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs);

  return scope.Close(actualBuffer);
}

static Handle<Value> bnToBinary(BIGNUM *bn) {
  if (!bn) return Null();
  Handle<Value> result;

  unsigned char *data = new unsigned char[BN_num_bytes(bn)];
  int len = BN_bn2bin(bn, data);
  if (len > 0) {
    result = makeBuffer(data, len);
  } else {
    result = Null();
  }
  delete[] data;

  return result;
}

static BIGNUM *binaryToBn(Handle<Value> &bin) {
  ssize_t len = DecodeBytes(bin);
  unsigned char *buf = new unsigned char[len];
  BIGNUM *result = BN_bin2bn(buf, len, NULL);
  delete[] buf;
  return result;
}

/**
 * Do not forget to call BIO_free() after use
 */
static BIO *binaryToBIO(Handle<Value> &bin) {
  BIO *bp = BIO_new(BIO_s_mem());
  if (!bp)
    return NULL;

  if (Buffer::HasInstance(bin)) {
    /* Copy only once for Buffer */
    Local<Object> buf = bin->ToObject();
    BIO_write(bp, Buffer::Data(buf), Buffer::Length(buf));

  } else {
    ssize_t len = DecodeBytes(bin);
    if (len >= 0) {
      char *buf = new char[len];
      len = DecodeWrite(buf, len, bin);
      // TODO: assert !res
      BIO_write(bp, buf, len);
      delete[] buf;
    } else {
      BIO_free(bp);
      return NULL;
    }
  }

  return bp;
}

void Key::Initialize (Handle<Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "generateRSA", GenerateRSA);
    NODE_SET_PROTOTYPE_METHOD(t, "readX509", ReadX509);
    NODE_SET_PROTOTYPE_METHOD(t, "readRSAPrivateKey", ReadRSAPrivateKey);
    NODE_SET_PROTOTYPE_METHOD(t, "readPUBKEY", ReadPUBKEY);
    NODE_SET_PROTOTYPE_METHOD(t, "toRSAPrivateKey", ToRSAPrivateKey);
    NODE_SET_PROTOTYPE_METHOD(t, "toPUBKEY", ToPUBKEY);
    NODE_SET_PROTOTYPE_METHOD(t, "getRSA", GetRSA);
    NODE_SET_PROTOTYPE_METHOD(t, "setRSA", SetRSA);

    target->Set(String::NewSymbol("Key"), t->GetFunction());
  }

Handle<Value> Key::New(const Arguments &args) {
  HandleScope scope;

  Key *key = new Key();
  key->Wrap(args.This());
  return args.This();
}


Key::Key ()
  : ObjectWrap(),
    pkey(NULL) {
}

void Key::KeyFree() {
  if (pkey) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }
}

Key::~Key () {
}

/*** generate() ***/

bool Key::KeyGenerateRSA() {
  bool result = false;
  KeyFree();

  BIGNUM *bn_e = NULL;
  BN_hex2bn(&bn_e, "10001");

  RSA *rsa = RSA_new(); 
  if (RSA_generate_key_ex(rsa, 2048, bn_e, NULL)) {
    pkey = EVP_PKEY_new();
    /* sets reference according to manpage, therefore don't free
       rsa */
    EVP_PKEY_assign_RSA(pkey, rsa);
    result = true;
  }

  BN_free(bn_e);
  return result;
}

Handle<Value> Key::GenerateRSA(const Arguments& args) {
  HandleScope scope;

  Key *key = ObjectWrap::Unwrap<Key>(args.This());
  key->KeyGenerateRSA();
  return args.This();
}

/*** loadX509() ***/

bool Key::KeyReadX509(Handle<Value> arg) {
  HandleScope scope;

  KeyFree();

  BIO *bp = binaryToBIO(arg);
  if (!bp)
    return false;

  X509 *x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
  // TODO: assert x509
  pkey = X509_get_pubkey(x509);
  if (!pkey)
    ERR_print_errors_fp(stderr);
  X509_free(x509);
  BIO_free(bp);

  return pkey ? true : false;
}

Handle<Value>
Key::ReadX509(const Arguments& args) {
  HandleScope scope;

  if (args.Length() == 1) {
    Key *key = ObjectWrap::Unwrap<Key>(args.This());
    if (key->KeyReadX509(args[0])) {
      printf("loaded public, pkey: %X\n", key->pkey);
      return args.This();
    } else {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }
  } else {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
}

/*** readRSAPrivateKey() ***/

// TODO: w/ passphrase
bool Key::KeyReadRSAPrivateKey(Handle<Value> arg) {
  HandleScope scope;

  KeyFree();

  BIO *bp = binaryToBIO(arg);
  if (!bp)
    return false;

  pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
  // TODO: assert pkey
  if (!pkey)
    ERR_print_errors_fp(stderr);
  BIO_free(bp);

  return true;
}

Handle<Value>
Key::ReadRSAPrivateKey(const Arguments& args) {
  HandleScope scope;

  if (args.Length() == 1) {
    Key *key = ObjectWrap::Unwrap<Key>(args.This());
    if (key->KeyReadRSAPrivateKey(args[0]))
      return args.This();
    else {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

  } else {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
}

/*** readPUBKEY() ***/

// TODO: w/ passphrase
bool Key::KeyReadPUBKEY(Handle<Value> arg) {
  HandleScope scope;

  KeyFree();

  BIO *bp = binaryToBIO(arg);
  if (!bp)
    return false;

  pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
  // TODO: assert pkey
  if (!pkey)
    ERR_print_errors_fp(stderr);
  BIO_free(bp);

  return true;
}

Handle<Value>
Key::ReadPUBKEY(const Arguments& args) {
  HandleScope scope;

  if (args.Length() == 1) {
    Key *key = ObjectWrap::Unwrap<Key>(args.This());
    if (key->KeyReadPUBKEY(args[0]))
      return args.This();
    else {
      Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
      return ThrowException(exception);
    }

  } else {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
}

/*** toRSAPrivateKey() ***/

Handle<Value> Key::KeyToRSAPrivateKey() {
  HandleScope scope;
  Handle<Value> result = Null();

  if (pkey && EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA) {
    BIO *bp = BIO_new(BIO_s_mem());

    struct rsa_st *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa) {
      if (PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL)) {
        char *data;
        long len = BIO_get_mem_data(bp, &data);
        result = scope.Close(Encode(data, len));
      }
    }

    BIO_free(bp);
  }

  return result;
}

Handle<Value> Key::ToRSAPrivateKey(const Arguments& args) {
  HandleScope scope;

  Key *key = ObjectWrap::Unwrap<Key>(args.This());
  return scope.Close(key->KeyToRSAPrivateKey());
}

/*** toPUBKEY() ***/

Handle<Value> Key::KeyToPUBKEY() {
  HandleScope scope;
  Handle<Value> result = Null();

  if (pkey) {
    BIO *bp = BIO_new(BIO_s_mem());

    if (PEM_write_bio_PUBKEY(bp, pkey)) {
        char *data;
        long len = BIO_get_mem_data(bp, &data);
        result = scope.Close(Encode(data, len));
    }

    BIO_free(bp);
  }

  return result;
}

Handle<Value> Key::ToPUBKEY(const Arguments& args) {
  HandleScope scope;

  Key *key = ObjectWrap::Unwrap<Key>(args.This());
  return scope.Close(key->KeyToPUBKEY());
}

/*** getRSA() ***/

Handle<Value> Key::KeyGetRSA() {
  HandleScope scope;

  if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA) {
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa) {
      Local<Object> result = Object::New();

      result->Set(String::NewSymbol("version"), bnToBinary(rsa->n));
      result->Set(String::NewSymbol("n"), bnToBinary(rsa->n));
      result->Set(String::NewSymbol("e"), bnToBinary(rsa->e));
      result->Set(String::NewSymbol("q"), bnToBinary(rsa->q));
      result->Set(String::NewSymbol("p"), bnToBinary(rsa->p));
      result->Set(String::NewSymbol("d"), bnToBinary(rsa->d));
      result->Set(String::NewSymbol("dmp1"), bnToBinary(rsa->dmp1));
      result->Set(String::NewSymbol("dmq1"), bnToBinary(rsa->dmq1));
      result->Set(String::NewSymbol("iqmp"), bnToBinary(rsa->iqmp));

      return scope.Close(result);
    } else {
      return Null();
    }
  } else {
    return Null();
  }
}

Handle<Value> Key::GetRSA(const Arguments& args) {
  HandleScope scope;

  Key *key = ObjectWrap::Unwrap<Key>(args.This());
  return key->KeyGetRSA();
}

/*** setRSA() ***/

// TODO: use RSA_check_key()

bool Key::KeySetRSA(Handle<Object> arg) {
  KeyFree();

  pkey = EVP_PKEY_new();
  RSA *rsa = RSA_new();
  EVP_PKEY_set1_RSA(pkey, rsa);

  Handle<Value> n = arg->Get(String::NewSymbol("n"));
  if (n->IsString() || Buffer::HasInstance(n)) {
    rsa->n = binaryToBn(n);
  }
  Handle<Value> e = arg->Get(String::NewSymbol("e"));
  if (e->IsString() || Buffer::HasInstance(e)) {
    rsa->e = binaryToBn(e);
  }

  return RSA_check_key(rsa);
}

/**
 * Only for public keys for now. Private ones need p, q, ... in
 * addition to d.
 */
Handle<Value>
Key::SetRSA(const Arguments& args) {
  HandleScope scope;

  if (args.Length() == 1 &&
      args[0]->IsObject()) {
    Key *key = ObjectWrap::Unwrap<Key>(args.This());
    if (key->KeySetRSA(args[0]->ToObject()))
      return args.This();
    else {
      Local<Value> exception = Exception::TypeError(String::New("Invalid RSA key"));
      return ThrowException(exception);
    }
  } else {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
}
