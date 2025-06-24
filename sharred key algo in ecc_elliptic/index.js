// ECDSA
var EC_DSA = require('elliptic').ec;

// Create and initialize EC context
// (better do it once and reuse it)
var ecdsa = new EC_DSA('secp256k1');

// Generate keys
var key = ecdsa.genKeyPair();

// Sign the message's hash (input must be an array, or a hex-string)
var msgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var signature = key.sign(msgHash);

// Export DER encoded signature in Array
var derSign = signature.toDER();

// Verify signature
console.log("ECDSA verification:", key.verify(msgHash, derSign));

// CHECK WITH NO PRIVATE KEY

var pubPoint = key.getPublic();
var x = pubPoint.getX();
var y = pubPoint.getY();

// Public Key MUST be either:
// 1) '04' + hex string of x + hex string of y; or
// 2) object with two hex string properties (x and y); or
// 3) object with two buffer properties (x and y)
var pub = pubPoint.encode('hex');                                 // case 1
// var pub = { x: x.toString('hex'), y: y.toString('hex') };         // case 2
// var pub = { x: x.toBuffer(), y: y.toBuffer() };                   // case 3
// var pub = { x: x.toArrayLike(Buffer), y: y.toArrayLike(Buffer) }; // case 3

// Import public key
var keyFromPublic = ecdsa.keyFromPublic(pub, 'hex');

// Signature MUST be either:
// 1) DER-encoded signature as hex-string; or
// 2) DER-encoded signature as buffer; or
// 3) object with two hex-string properties (r and s); or
// 4) object with two buffer properties (r and s)

// To verify, we will use the derSign from before which is an array of bytes
// console.log(keyFromPublic.verify(msgHash, derSign));


// EdDSA
var EdDSA = require('elliptic').eddsa;

// Create and initialize EdDSA context
// (better do it once and reuse it)
var eddsa = new EdDSA('ed25519');

// Create key pair from secret
var secret = '693e3c...'; // Replace with a real secret
var edKey = eddsa.keyFromSecret(secret); 

// Sign the message's hash (input must be an array, or a hex-string)
var edMsgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var edSignature = edKey.sign(edMsgHash).toHex();

// Verify signature
// console.log("EdDSA verification:", edKey.verify(edMsgHash, edSignature));

// CHECK WITH NO PRIVATE KEY

// Import public key
var edPub = '0a1af638...'; // Replace with a real public key
var edKeyFromPublic = eddsa.keyFromPublic(edPub, 'hex');

// Verify signature
var edSignatureToVerify = '70bed1...'; // Replace with a real signature
// console.log("EdDSA verification (no private key):", edKeyFromPublic.verify(edMsgHash, edSignatureToVerify));


// ECDH
var EC_DH = require('elliptic').ec;
var ecdh = new EC_DH('curve25519');

// Generate keys
var key1 = ecdh.genKeyPair();
var key2 = ecdh.genKeyPair();

var shared1 = key1.derive(key2.getPublic());
var shared2 = key2.derive(key1.getPublic());

console.log('Both shared secrets are BN instances');
console.log("Shared secret 1:", shared1.toString(16));
console.log("Shared secret 2:", shared2.toString(16));

// three and more members:
var A = ecdh.genKeyPair();
var B = ecdh.genKeyPair();
var C = ecdh.genKeyPair();

var AB = A.getPublic().mul(B.getPrivate());
var BC = B.getPublic().mul(C.getPrivate());
var CA = C.getPublic().mul(A.getPrivate());

var ABC = AB.mul(C.getPrivate());
var BCA = BC.mul(A.getPrivate());
var CAB = CA.mul(B.getPrivate());

console.log("ABC:", ABC.getX().toString(16));
console.log("BCA:", BCA.getX().toString(16));
console.log("CAB:", CAB.getX().toString(16));