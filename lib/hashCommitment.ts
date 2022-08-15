import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"

type TCurve = any
type TCurvePoint = any

export namespace HashCommitment {

export function createComWithBlind (message: BN, blindFactor: BN): BN {
  const sha256 = cryptoJS.algo.SHA256.create()
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(blindFactor.toString(16))))
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(message.toString(16))))
  const dig = sha256.finalize()
  return new BN(cryptoJS.enc.Hex.stringify(dig), 16)
}

export function createComWithBlindFromMsgArray (messageArray: BN[], blindFactor: BN): BN {
  const sha256 = cryptoJS.algo.SHA256.create()
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(blindFactor.toString(16))))
  for(let i = 0; i < messageArray.length; i++){
    sha256.update(Hex.toCryptoJSBytes(Hex.padEven(messageArray[i].toString(16))))
  }
  const dig = sha256.finalize()
  return new BN(cryptoJS.enc.Hex.stringify(dig), 16)
}

export function createComWithBlindFromCurvePoint (curvePoint: TCurvePoint, blindFactor: BN) : BN{
  const sha256 = cryptoJS.algo.SHA256.create()
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(blindFactor.toString(16))))
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(curvePoint.getX().toString(16))))
  sha256.update(Hex.toCryptoJSBytes(Hex.padEven(curvePoint.getY().toString(16))))
  const dig = sha256.finalize()
  return new BN(cryptoJS.enc.Hex.stringify(dig), 16)
}

}
