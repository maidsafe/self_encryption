import test from 'ava'
import fs from 'fs/promises'
import fsBlocking from 'fs'
import crypto from 'crypto'
import path from 'path'

import { XorName, decryptFromStorage, streamingDecryptFromStorage, encrypt, encryptFromFile } from '../index.js'

let fileName1, fileName2, fileName3, fileName4, dirName1

test('decryptFromStorage', async (t) => {
  const data = Buffer.from('Hello, World!');
  const { dataMap, chunks } = encrypt(data)
  const infos = dataMap.infos()

  const getChunk = (xorNameHexStr) => {
    const xorName = XorName.fromHex(xorNameHexStr)

    for (const info of infos) {
      if (Buffer.from(info.dstHash.asBytes()).equals(xorName.asBytes())) {
        return chunks[info.index].content()
      }
    }

    throw new Error(`No chunk found for XOR: ${xorNameHexStr}`)
  }

  fileName1 = crypto.randomBytes(16).toString('hex')
  decryptFromStorage(dataMap, fileName1, getChunk)
  const dataRead = await fs.readFile(fileName1)

  t.deepEqual(dataRead, data)
})

test('streamingDecryptFromStorage', async (t) => {
  const data = Buffer.from('Hello, World!');
  const { dataMap, chunks } = encrypt(data)
  const infos = dataMap.infos()

  const getChunkParallel = (hexStrXorNames, abc) => {
    let chunkData = []
    for (const hexStrXorName of hexStrXorNames) {
      const xorName = XorName.fromHex(hexStrXorName)
      let found = false
      for (const info of infos) {
        if (Buffer.from(info.dstHash.asBytes()).equals(xorName.asBytes())) {
          chunkData.push(chunks[info.index].content())
          found = true
          break
        }
      }
      if (!found) {
        throw new Error(`No chunk found for XOR: ${xorNameHexStr}`)
      }
    }

    return chunkData
  }

  fileName2 = crypto.randomBytes(16).toString('hex')
  streamingDecryptFromStorage(dataMap, fileName2, getChunkParallel)
  const dataRead = await fs.readFile(fileName2)

  t.deepEqual(dataRead, data)
})

test('encryptFromFile and decryptFromStorage', async (t) => {
  const data = Buffer.from('Hello, World!');
  fileName3 = crypto.randomBytes(16).toString('hex')
  await fs.writeFile(fileName3, data)

  dirName1 = crypto.randomBytes(16).toString('hex')
  await fs.mkdir(dirName1)
  const { dataMap, chunkNames } = encryptFromFile(fileName3, dirName1)

  const getChunk = (xorNameHexStr) => {
    return fsBlocking.readFileSync(dirName1 + path.sep + xorNameHexStr)
  }

  fileName4 = crypto.randomBytes(16).toString('hex')
  decryptFromStorage(dataMap, fileName4, getChunk)
  const dataRead = await fs.readFile(fileName3)

  t.deepEqual(dataRead, data)
})

test.after.always('cleanup temporary files', async t => {
  const rmOptions = { recursive: true, force: true };
  if (fileName1) await fs.rm(fileName1, rmOptions)
  if (fileName2) await fs.rm(fileName2, rmOptions)
  if (fileName3) await fs.rm(fileName3, rmOptions)
  if (fileName4) await fs.rm(fileName4, rmOptions)
  if (dirName1) await fs.rm(dirName1, rmOptions)
});
