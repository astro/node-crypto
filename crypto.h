void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest, int* md_hex_len);
void hex_decode(unsigned char *input, int length, char** buf64, int* buf64_len);
void base64(unsigned char *input, int length, char** buf64, int* buf64_len);
void *unbase64(unsigned char *input, int length, char** buffer, int* buffer_len);
