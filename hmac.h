#include <node.h>
#include <openssl/hmac.h>

using namespace v8;
using namespace node;

class Hmac : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool HmacInit(char* hashType, char* key, int key_len);
  int HmacUpdate(char* data, int len);
  int HmacDigest(unsigned char** md_value, unsigned int *md_len);
  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    HmacInit(const Arguments& args);
  static Handle<Value>
    HmacUpdate(const Arguments& args);
  static Handle<Value>
    HmacDigest(const Arguments& args);
  Hmac ();
  ~Hmac ();

 private:

  HMAC_CTX ctx;
  const EVP_MD *md;
  bool initialised;

};
