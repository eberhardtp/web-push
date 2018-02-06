package com.zivver.webpush

import java.math.BigInteger
import java.security._
import java.util.Base64

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.{ECPrivateKey, ECPublicKey}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.{ECNamedCurveParameterSpec, ECPrivateKeySpec, ECPublicKeySpec}

object Utils {

  private val securityProvider: Provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)

  def savePublicKey(publicKey: ECPublicKey): Array[Byte] = publicKey.getQ.getEncoded(false)

  def savePrivateKey(privateKey: ECPrivateKey): Array[Byte] = privateKey.getD.toByteArray

  def base64Decode(base64Encoded: String): Array[Byte] = {
    if (base64Encoded.contains("+") || base64Encoded.contains("/")) Base64.getDecoder.decode(base64Encoded)
    else Base64.getUrlDecoder.decode(base64Encoded)
  }

  def loadPublicKey(encodedPublicKey: String): PublicKey = {
    val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1")
    KeyFactory.getInstance("ECDH", securityProvider)
      .generatePublic(new ECPublicKeySpec(ecSpec.getCurve.decodePoint(base64Decode(encodedPublicKey)), ecSpec))
  }

  def loadPrivateKey(encodedPrivateKey: String): PrivateKey = {
    KeyFactory.getInstance("ECDH", securityProvider)
      .generatePrivate(new ECPrivateKeySpec(new BigInteger(base64Decode(encodedPrivateKey)),
        ECNamedCurveTable.getParameterSpec("prime256v1")))
  }

  def toJsonString(json: Map[String, String]): String = {
    json.map { case (k, v) => s""""$k":"$v"""" }.mkString("{", ",", "}")
  }

}
