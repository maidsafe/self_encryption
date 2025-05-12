import test from 'ava'

import { encrypt, decrypt, verifyChunk } from '../index.js'

test('encrypt and decrypt', async (t) => {
    const data = Buffer.from("Hello, World!");
    const { dataMap, chunks } = encrypt(data)
    const dataDecrypted = decrypt(dataMap, chunks)
    t.deepEqual(Buffer.from(dataDecrypted), data)
})

test('verify chunk', async (t) => {
    t.plan(0) // Expect no assertions in this test

    const data = Buffer.from("Hello, World!");
    const { dataMap, chunks } = encrypt(data)
    const infos = dataMap.infos()
    for (const [i, info] of infos.entries()) {
        verifyChunk(info.dstHash, chunks[i].content())
    }
})
