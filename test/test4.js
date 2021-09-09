const rabe = require('../rabe.node')
const [pk,msk] = rabe.setup()

const buf = Buffer.from('bella secco');

const ciphertext = rabe.encrypt(pk,'"A" and "B" and "C"',buf)
const sk = rabe.keygen(pk,msk,JSON.stringify(["A","B","C"]))
const res_buf = rabe.decrypt(sk,ciphertext)

console.log(res_buf.toString())
