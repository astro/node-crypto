#include <node.h>
#include <openssl/evp.h>

using namespace v8;
using namespace node;

class Verify : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool VerifyInit (const char* verifyType);
  int VerifyUpdate(char* data, int len);
  int VerifyFinal(char* keyPem, int keyPemLen, unsigned char* sig, int siglen);

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    VerifyInit(const Arguments& args);
  static Handle<Value>
    VerifyUpdate(const Arguments& args);
  static Handle<Value>
    VerifyFinal(const Arguments& args);
  Verify ();
  ~Verify ();

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};
