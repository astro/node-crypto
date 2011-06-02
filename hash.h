#include <node.h>

using namespace v8;
using namespace node;

class Hash : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool HashInit (const char* hashType);
  int HashUpdate(char* data, int len);
  int HashDigest(unsigned char** md_value, unsigned int *md_len);

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    HashInit(const Arguments& args);
  static Handle<Value>
    HashUpdate(const Arguments& args);
  static Handle<Value>
    HashDigest(const Arguments& args);
  Hash ();
  ~Hash ();

 private:

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  bool initialised;

};
