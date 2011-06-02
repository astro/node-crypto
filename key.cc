#include <node_buffer.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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

void Key::Initialize (Handle<Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "loadPublic", LoadPublic);
    NODE_SET_PROTOTYPE_METHOD(t, "getRSA", GetRSA);

    target->Set(String::NewSymbol("Key"), t->GetFunction());
  }

Handle<Value> Key::New(const Arguments &args) {
  HandleScope scope;

  Key *key = new Key();
  if (args.Length() > 0)
    key->KeyLoadPublic(args[0], args.This());

  key->Wrap(args.This());
  return args.This();
}

void Key::KeyFree() {
  if (pkey) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }
}

Handle<Value> Key::KeyLoadPublic(Handle<Value> arg, Local<Object> This) {
  HandleScope scope;

  KeyFree();

  BIO *bp = BIO_new(BIO_s_mem());
  // TODO: assert bp

  if (arg->IsString()) {
    Local<String> s = arg->ToString();
    // TODO: assert !res
    int len = s->Length();
    char *buf = new char[len];
    BIO_write(bp, buf, len);
    delete[] buf;

    return This;
  } else if (Buffer::HasInstance(arg)) {
    Local<Object> buf = arg->ToObject();
    BIO_write(bp, Buffer::Data(buf), Buffer::Length(buf));
  } else {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  X509 *x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
  // TODO: assert x509
  pkey = X509_get_pubkey(x509);
  X509_free(x509);
  BIO_free(bp);
}

Handle<Value>
Key::LoadPublic(const Arguments& args) {
  HandleScope scope;

  if (args.Length() == 1) {
    Key *key = ObjectWrap::Unwrap<Key>(args.This());
    return key->KeyLoadPublic(args[0], args.This());
  } else {
    /* TODO: also w/ buffer */
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }
}

Handle<Value> Key::KeyGetRSA() {
  HandleScope scope;

  if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA) {
    struct rsa_st *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa) {
      Local<Object> result = Object::New();

      result->Set(String::NewSymbol("n"), bnToBinary(rsa->n));
      result->Set(String::NewSymbol("e"), bnToBinary(rsa->e));

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


Key::Key ()
  : ObjectWrap(),
    pkey(NULL) {
}

Key::~Key () {
}
