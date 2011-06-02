#include <node.h>

using namespace v8;
using namespace node;

class Sign : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool SignInit (const char* signType);
  int SignUpdate(char* data, int len);
  int SignFinal(unsigned char** md_value, unsigned int *md_len, char* keyPem, int keyPemLen);

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    SignInit(const Arguments& args);
  static Handle<Value>
    SignUpdate(const Arguments& args);
  static Handle<Value>
    SignFinal(const Arguments& args);
  Sign ();
  ~Sign ();

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};
