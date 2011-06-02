var crypto=require("./crypto");
var sys=require("sys");
var fs=require("fs");
var assert=require("assert");


// Test HMAC
var h1 = (new crypto.Hmac).init("sha1", "Node").update("some data").update("to hmac").digest("hex");
assert.equal(h1, '19fd6e1ba73d9ed2224dd5094a71babe85d9a892', "test HMAC");

// Test hashing
var a0 = (new crypto.Hash).init("sha1").update("Test123").digest("hex");
var a1 = (new crypto.Hash).init("md5").update("Test123").digest("binary");
var a2=  (new crypto.Hash).init("sha256").update("Test123").digest("base64");
var a3 = (new crypto.Hash).init("sha512").update("Test123").digest(); // binary

// Test multiple updates to same hash
var h1 = (new crypto.Hash).init("sha1").update("Test123").digest("hex");
var h2 = (new crypto.Hash).init("sha1").update("Test").update("123").digest("hex");
assert.equal(h1, h2, "multipled updates");


// Load our public and private keys
var keyPem = fs.readFileSync("test_key.pem");
var certPem = fs.readFileSync("test_cert.pem");

// Test signing and verifying
var s1 = (new crypto.Sign).init("RSA-SHA1").update("Test123").sign(keyPem, "base64");
var verified = !!((new crypto.Verify).init("RSA-SHA1").update("Test").update("123").verify(certPem, s1, "base64"));
assert.ok(verified, "sign and verify (base 64)");

var s2 = (new crypto.Sign).init("RSA-SHA256").update("Test123").sign(keyPem); // binary
var verified = !!((new crypto.Verify).init("RSA-SHA256").update("Test").update("123").verify(certPem, s2)); // binary
assert.ok(verified, "sign and verify (binary)");

// Test encryption and decryption
var plaintext="Keep this a secret? No! Tell everyone about node.js!";

var cipher=(new crypto.Cipher).init("aes192", "MySecretKey123");
var ciph=cipher.update(plaintext, 'utf8', 'hex'); // encrypt plaintext which is in utf8 format to a ciphertext which will be in hex
ciph+=cipher.final('hex'); // Only use binary or hex, not base64.

var decipher=(new crypto.Decipher).init("aes192", "MySecretKey123");
var txt = decipher.update(ciph, 'hex', 'utf8');
txt += decipher.final('utf8');
assert.equal(txt, plaintext, "encryption and decryption");

// Test encyrption and decryption with explicit key and iv
var encryption_key='0123456789abcd0123456789';
var iv = '12345678';

var cipher=(new crypto.Cipher).initiv("des-ede3-cbc", encryption_key, iv);

var ciph=cipher.update(plaintext, 'utf8', 'hex');
ciph+=cipher.final('hex');

var decipher=(new crypto.Decipher).initiv("des-ede3-cbc",encryption_key,iv);
var txt = decipher.update(ciph, 'hex', 'utf8');
txt += decipher.final('utf8');
assert.equal(txt, plaintext, "encryption and decryption with key and iv");

var key=(new crypto.Key);
key.loadPublic(certPem);
var rsa = key.getRSA();
assert.equal("\x01\x00\x01", rsa.e.toString());
assert.equal("\xf1\xdf\x07\x73\xa6\xad\xab\xbf\x09\xb7\x51\xcb\xa7\xd6" +
             "\xa0\x03\xfc\x29\x41\xfb\x05\xbe\x46\x14\x75\x9d\x58\xb1\xdb" +
             "\xce\x90\xbd\xa3\x6a\x78\xf0\x1d\x08\x0c\x30\x2c\xbf\x36\x36" +
             "\xa5\xdc\x55\x04\x5b\x43\x8b\x3d\xe6\xca\x65\x42\x7c\x2f\x8e" +
             "\x09\x05\x74\xa5\x57\x15\x38\xcf\x28\xa2\x48\xe5\xa5\x77\xc1" +
             "\x24\x4d\xeb\x51\x01\x54\xf7\x58\xa4\x2a\xde\xe7\x7e\x72\x7c" +
             "\x6f\xee\x0f\x2b\x19\x14\x29\xd5\x41\xd9\xc2\x67\x5b\x67\x5c" +
             "\x04\x7c\x06\x2a\xf1\x08\xd8\xc7\xa9\xb5\x72\x23\x20\x46\x8e" +
             "\xc3\x68\x34\x21\x0f\x6f\x64\x77\xe5", rsa.n.toString('binary'));