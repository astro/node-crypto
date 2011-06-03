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

var e = "\x01\x00\x01";
var n = "\xf1\xdf\x07\x73\xa6\xad\xab\xbf\x09\xb7\x51\xcb\xa7\xd6" +
	"\xa0\x03\xfc\x29\x41\xfb\x05\xbe\x46\x14\x75\x9d\x58\xb1\xdb" +
	"\xce\x90\xbd\xa3\x6a\x78\xf0\x1d\x08\x0c\x30\x2c\xbf\x36\x36" +
	"\xa5\xdc\x55\x04\x5b\x43\x8b\x3d\xe6\xca\x65\x42\x7c\x2f\x8e" +
	"\x09\x05\x74\xa5\x57\x15\x38\xcf\x28\xa2\x48\xe5\xa5\x77\xc1" +
	"\x24\x4d\xeb\x51\x01\x54\xf7\x58\xa4\x2a\xde\xe7\x7e\x72\x7c" +
	"\x6f\xee\x0f\x2b\x19\x14\x29\xd5\x41\xd9\xc2\x67\x5b\x67\x5c" +
	"\x04\x7c\x06\x2a\xf1\x08\xd8\xc7\xa9\xb5\x72\x23\x20\x46\x8e" +
	"\xc3\x68\x34\x21\x0f\x6f\x64\x77\xe5";
var d = "\x93\x5e\x9b\xd0\xb8\x7e\xda\xc5\x34\x6b\x50\xd8\x30\x74" +
    "\x51\xdc\xfb\xb8\x3b\xae\x71\xea\x64\x12\xb5\x32\xe0\xc6\xc5" +
    "\xb1\xcf\x78\xec\x67\xc4\x36\x30\xca\x25\x7a\xf8\xd8\xac\x74" +
    "\x91\x8c\x74\xf4\x89\x92\xd6\xf5\x29\x78\xaa\x47\xdf\x18\xae" +
    "\x87\x0a\x9e\xee\xd9\xb8\x16\xc0\x81\x83\x84\xd8\xa9\x09\x5e" +
    "\xd7\x8a\x31\xc6\x6e\xd3\x35\xe0\x70\xc0\x60\xb7\x38\x1e\xe1" +
    "\x8a\x89\x1b\x68\x08\xdb\x3d\x9d\x61\x02\xe3\x6c\xea\x6b\x37" +
    "\x61\xbb\xef\x8f\xa2\xe6\xc7\x3c\x78\xda\x6f\x0e\xe4\x35\xc2" +
    "\x1b\x6f\xdf\xf8\xa3\x2f\x68\xd5\x21";
var p = "\xfd\xe9\x2b\x3a\xc5\xa4\x36\x85\xbd\xda\x7d\xe6\xfa\x6b" +
    "\x1d\x56\xec\x5e\x7a\x4e\x01\xf3\xb1\x28\x4c\xeb\x73\x09\x76" +
    "\xf5\x77\x26\xc8\x65\x45\x6f\xe0\x9e\x3c\x54\x08\x8c\xe3\x78" +
    "\x61\x64\x75\x99\x72\x4d\x9b\xa0\x3f\xe1\x87\x08\xc2\x33\x93" +
    "\x56\x77\x8a\x18\xe9";
var q = "\xf3\xdc\x80\x15\x4d\x74\xd6\x52\x67\xc8\x51\xe2\x88\x08" +
    "\xe2\x7c\xf0\x5a\xb4\x21\x97\xd3\x11\x6e\xaa\xad\x7c\xe9\xf6" +
    "\x4c\xaf\xed\x8c\xcb\xf5\xd0\x02\xe0\x94\xf9\xa7\xdd\x26\x8f" +
    "\x48\xd4\x4f\x28\x3d\xa1\xa0\xb6\xc5\xb8\x71\x44\x46\x57\x12" +
    "\xef\xda\x5b\x09\x9d";

var key=(new crypto.Key);
key.loadPublic(certPem);
var rsa = key.getRSA();
assert.equal(e, rsa.e.toString('binary'));
assert.equal(n, rsa.n.toString('binary'));

key=(new crypto.Key);
key.loadPrivate(keyPem);
rsa = key.getRSA();
assert.equal(e, rsa.e.toString('binary'));
assert.equal(n, rsa.n.toString('binary'));
assert.equal(p, rsa.p.toString('binary'));
assert.equal(q, rsa.q.toString('binary'));
assert.equal(d, rsa.d.toString('binary'));

key=(new crypto.Key);
assert.ok(key.generate());
rsa = key.getRSA();
assert.ok(rsa.e.length);
assert.ok(rsa.n.length);
assert.ok(rsa.p.length);
assert.ok(rsa.q.length);
assert.ok(rsa.d.length);
