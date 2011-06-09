#include <node.h>
#include <openssl/evp.h>

using namespace v8;
using namespace node;

class Key : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool KeyGenerateRSA();
  bool KeyReadX509(Handle<Value> arg);
  bool KeyReadPrivate(Handle<Value> arg);
  Handle<Value> KeyToString();
  Handle<Value> KeyGetRSA();
  bool KeySetRSA(Handle<Object> arg);
  void KeyFree();

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value> 
    GenerateRSA(const Arguments& args);
  static Handle<Value>
    ReadX509(const Arguments& args);
  static Handle<Value>
    ReadPrivate(const Arguments& args);
  static Handle<Value>
    ToString(const Arguments& args);
  static Handle<Value>
    GetRSA(const Arguments& args);
  static Handle<Value>
    SetRSA(const Arguments& args);
  Key ();
  ~Key ();

 private:

  EVP_PKEY *pkey;

};
