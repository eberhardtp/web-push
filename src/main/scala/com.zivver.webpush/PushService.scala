package com.zivver.webpush

import java.security._
import java.util.Base64

import akka.http.scaladsl.model.headers.RawHeader
import akka.http.scaladsl.model.{HttpMethods, HttpRequest, HttpResponse}
import com.zivver.webpush.Encryption.Encrypted
import org.bouncycastle.jce.interfaces.ECPublicKey
import pdi.jwt.Jwt
import pdi.jwt.JwtAlgorithm.ES256

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._

/**
  * Push service.
  */
case class PushService(publicKey: PublicKey, privateKey: PrivateKey, subject: String, processRequest: HttpRequest => Future[HttpResponse], exp: FiniteDuration = 12.hours) {

  private val base64encoder = Base64.getUrlEncoder
  val defaultTtl: Int = 2419200

  private val cryptoKey = base64encoder.withoutPadding().encodeToString(Utils.savePublicKey(publicKey.asInstanceOf[ECPublicKey]))

  /**
    * Send a data free push notification.
    *
    * @param subscription Browser subscription object.
    * @return HttpResponse from push server.
    */
  def send(subscription: Subscription)(implicit ec: ExecutionContext): Future[HttpResponse] = send(subscription, None, defaultTtl)

  /**
    * Send a data free push notification.
    *
    * @param subscription Browser subscription object.
    * @param ttl          Suggestion to the message server for how long it should keep the message
    *                     and attempt to deliver it.
    * @return HttpResponse from push server.
    */
  def send(subscription: Subscription, ttl: Int)(implicit ec: ExecutionContext): Future[HttpResponse] = send(subscription, None, ttl)

  /**
    * Sends a data bearing push notification.
    *
    * @param subscription Browser subscription object.
    * @param payload      Push notification payload.
    * @param ttl          Optional suggestion to the message server for how long it should keep the message
    *                     and attempt to deliver it. If not specified default value will be used.
    * @return HttpResponse from push server.
    */
  def send(subscription: Subscription, payload: String, ttl: Int)(implicit ec: ExecutionContext): Future[HttpResponse] = send(subscription, Some(payload.getBytes), ttl)

  def send(subscription: Subscription, payload: String)(implicit ec: ExecutionContext): Future[HttpResponse] = send(subscription, Some(payload.getBytes), defaultTtl)

  /**
    *
    * Sends a data bearing push notification.
    *
    * @param subscription Browser subscription object.
    * @param payload      Push notification data as a Byte Array.
    * @param ttl          Optional suggestion to the message server for how long it should keep the message
    *                     and attempt to deliver it. If not specified default value will be used.
    * @return HttpResponse from push server.
    */
  def send(subscription: Subscription, payload: Array[Byte], ttl: Int = defaultTtl)(implicit ec: ExecutionContext): Future[HttpResponse] = send(subscription, Some(payload), ttl)

  private def send(subscription: Subscription, payload: Option[Array[Byte]], ttl: Int)(implicit ec: ExecutionContext) = {

    val vapidHeaderF = vapidHeaders(subscription.origin, ttl)

    def httpRequestSetupF(vapidHeaders: Map[String, String]) = Future {
      var httpRequest =
        HttpRequest(
          method = HttpMethods.POST,
          uri = subscription.endpoint
        )

      payload.fold(vapidHeaders) {
        p =>
          val (encryptionHeaders, content) = handleEncryption(p, subscription)
          httpRequest = httpRequest.withEntity(content)
          encryptionHeaders
      }.foreach {
        case (k, v) =>
          httpRequest = httpRequest.addHeader(RawHeader(k, v))
      }

      vapidHeaders.map { e =>
        httpRequest = httpRequest.addHeader(RawHeader(e._1, e._2))
      }
      httpRequest
    }

    for {
      vapidHeaders <- vapidHeaderF
      httpRequest <- httpRequestSetupF(vapidHeaders)
      httpResponse <- processRequest(httpRequest)
    } yield httpResponse

  }

  def vapidHeaders(origin: String, ttl: Int)(implicit ex: ExecutionContext): Future[Map[String, String]] = Future {
    Map(
      "TTL" -> ttl.toString,
      "Authorization" -> (
        "WebPush " + Jwt.encode(Utils.toJsonString(Map(
          "aud" -> origin,
          "exp" -> ((System.currentTimeMillis() + exp.toMillis) / 1000).toString,
          "sub" -> subject
        )), privateKey, ES256)),
      "Crypto-Key" -> ("p256ecdsa=" + cryptoKey)
    )
  }

  private def handleEncryption(payload: Array[Byte], subscription: Subscription): (Map[String, String], Array[Byte]) = {
    val encrypted: Encrypted = Encryption.encrypt(payload, subscription.publicKey, subscription.auth)
    (Map(
      "Content-Encoding" -> "aesgcm",
      "Encryption" -> ("keyid=p256dh;salt=" + base64encoder.withoutPadding().encodeToString(encrypted.salt)),
      "Crypto-Key" -> ("keyid=p256dh;dh=" + base64encoder.encodeToString(Utils.savePublicKey(encrypted.publicKey.asInstanceOf[ECPublicKey])) +
        ";p256ecdsa=" + cryptoKey)
    ), encrypted.ciphertext)
  }

  def getHttpRequest(subscription: Subscription, payload: Option[Array[Byte]], vapidHeader: Map[String, String])(implicit ex: ExecutionContext): Future[HttpRequest] = Future {
    var httpRequest =
      HttpRequest(
        method = HttpMethods.POST,
        uri = subscription.endpoint
      )
    payload.fold(vapidHeader) {
      p =>
        val (encryptionHeaders, content) = handleEncryption(p, subscription)
        httpRequest = httpRequest.withEntity(content)
        encryptionHeaders
    }.foreach {
      case (k, v) =>
        httpRequest = httpRequest.addHeader(RawHeader(k, v))
    }
    vapidHeader.map { e =>
      httpRequest = httpRequest.addHeader(RawHeader(e._1, e._2))
    }
    httpRequest
  }

}
