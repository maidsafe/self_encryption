import test from 'ava'

import { decryptFromStorage, encrypt } from '../index.js'

test('decryptFromStorage', async (t) => {
  const data = Buffer.from("Hello, World!");
  const { dataMap, chunks } = encrypt(data)
  const infos = dataMap.infos()
  console.log('====> C')
  const getChunk = (xorName) => {
    console.log('====> D')
    console.dir(xorName)
    for (const info of infos) {
      console.log('====> E')
      console.log('====> E')
      if (info.dstHash.asBytes().equals(xorName)) {
        console.log("equal")
        return chunks[info.index].content()
      } else {
        console.log("not equal")
        throw new Error("big trouble")
      }
    }
  }
  decryptFromStorage(dataMap, "hello-world", getChunk)
})
