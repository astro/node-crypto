#include <node.h>

using namespace v8;
using namespace node;

class Decipher : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool DecipherInit(char* cipherType, char* key_buf, int key_buf_len);
  bool DecipherInitIv(char* cipherType, char* key, int key_len, char *iv, int iv_len);
  int DecipherUpdate(char* data, int len, unsigned char** out, int* out_len);
  int DecipherFinal(unsigned char** out, int *out_len, bool tolerate_padding);

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    DecipherInit(const Arguments& args);
  static Handle<Value>
    DecipherInitIv(const Arguments& args);
  static Handle<Value>
    DecipherUpdate(const Arguments& args);
  static Handle<Value>
    DecipherFinal(const Arguments& args);
  static Handle<Value>
    DecipherFinalTolerate(const Arguments& args);
  Decipher ();
  ~Decipher ();

 private:

  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher;
  bool initialised;
  unsigned char* incomplete_utf8;
  int incomplete_utf8_len;
  char incomplete_hex;
  bool incomplete_hex_flag;
};
