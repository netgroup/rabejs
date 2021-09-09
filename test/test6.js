const rabe = require('../rabe.node')
const fs = require('fs');

const buf = fs.readFileSync('./test/img2.jpg');

const [pk,msk] = rabe.setup()

const ciphertext = rabe.encrypt(pk,'"A" and "B" and "C"',buf)
const sk = rabe.keygen(pk,msk,JSON.stringify(["A","B","C"]))
const res_buf = rabe.decrypt(sk,ciphertext)

fs.writeFileSync('./test/img2copy.jpg',res_buf);
