/* Hybrid encryption test file */

const buffer = require('buffer');

const crypto = require('crypto');

const rabe = require('../rabe.node')
const fs = require('fs');

// Data reading
const buf = fs.readFileSync('./test/img2.jpg').toString('hex');
//const buf = 'aaaabbbcc'


/********** SETUP *********/

// ABE keys generation
const [pk,msk] = rabe.setup()
const sk = rabe.keygen(pk,msk,JSON.stringify(["A","B","C"]))

// Symmetric key generation
const sym_key = crypto.randomBytes(32)

// Symmetric cipher initialisation
const algorithm = "aes-256-cbc"; 
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv(algorithm, sym_key, iv);


/******* ENCRYPTION *******/

// Data symmetric encryption (DEM)
let ciphertext = cipher.update(buf, "utf-8", "hex");
ciphertext += cipher.final("hex");

console.log("================= Encrypted message: " + ciphertext);
//const ciphertext = cryptojs.AES.encrypt(buf, sym_key).toString();

// Symmetric key encryption (KEM)
const enc_sym_key = rabe.encrypt(pk, '"A" and "B" and "C"', sym_key)


/******* DECRYPTION *******/

// Encrypted symmetric key decryption
const dec_sym_key = rabe.decrypt(sk, enc_sym_key)

// Ciphertext decryption
//const dec_buf = cryptojs.AES.decrypt(ciphertext, dec_sym_key);
const decipher = crypto.createDecipheriv(algorithm, dec_sym_key, iv);
let dec_buf = decipher.update(ciphertext, "hex", "utf-8");
dec_buf += decipher.final("utf8");

console.log("============== Decrypted message: " + dec_buf);

fs.writeFileSync('./test/img2copy.jpg', buffer.Buffer.from(dec_buf, 'hex'));

