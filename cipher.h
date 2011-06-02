#include <node.h>

using namespace v8;
using namespace node;

class Cipher : public ObjectWrap {
 public:
  static void
    Initialize (v8::Handle<v8::Object> target);
  bool CipherInit(char* cipherType, char* key_buf, int key_buf_len);
  bool CipherInitIv(char* cipherType, char* key, int key_len, char *iv, int iv_len);
  int CipherUpdate(char* data, int len, unsigned char** out, int* out_len);
  int CipherFinal(unsigned char** out, int *out_len);

 protected:

  static Handle<Value>
    New (const Arguments& args);
  static Handle<Value>
    CipherInit(const Arguments& args);
  static Handle<Value>
    CipherInitIv(const Arguments& args);
  static Handle<Value>
    CipherUpdate(const Arguments& args);
  static Handle<Value>
    CipherFinal(const Arguments& args);
  Cipher ();
  ~Cipher ();

 private:

  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher;
  bool initialised;
  char* incomplete_base64;
  int incomplete_base64_len;

};
