import test from 'ava'

import { encrypt, decrypt } from '../index.js'

test('encrypt and decrypt', async (t) => {
    const data = Buffer.from("Hello, World!");
    const { dataMap, chunks } = encrypt(data)
    const dataDecrypted = decrypt(dataMap, chunks)
    t.deepEqual(Buffer.from(dataDecrypted), data)
})
