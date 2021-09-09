const rabe = require('../rabe.node')
const [pk,msk] = rabe.setup()

const ciphertext = rabe.encrypt_str(pk,'"A" and "B" and "C"',"bella secco")
const sk = rabe.keygen(pk,msk,JSON.stringify(["A","B","C"]))
const res = rabe.decrypt_str(sk,ciphertext)

console.log(res)
