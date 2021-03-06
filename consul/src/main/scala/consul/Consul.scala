package consul

import java.io.{ByteArrayInputStream, StringReader}
import java.security.cert.{Certificate, CertificateFactory, X509Certificate}
import java.security.{KeyStore, PrivateKey, Security}
import java.util.concurrent.atomic.AtomicBoolean

import com.twitter.finagle.{Http, http}
import com.twitter.finagle.http.service.HttpResponseClassifier
import com.twitter.finagle.http.{Method, Request, Status}
import com.twitter.finagle.service.ResponseClass
import com.twitter.io.Buf
import com.twitter.logging.Logger
import com.twitter.util._
import io.circe.Decoder
import io.circe.generic.auto._
import io.circe.parser._
import io.circe.syntax._
import javax.net.ssl.{KeyManagerFactory, SSLSession, TrustManagerFactory}
import org.bouncycastle.asn1.x509.{Certificate => BCCertificate}
import org.bouncycastle.asn1.{ASN1ObjectIdentifier, ASN1OctetString, ASN1Sequence, ASN1TaggedObject}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}


trait ConsulKeyStore {
  def apply(privateKey: PrivateKey, certificate: Certificate): Unit
}

trait ConsulCAKeyStore {
  def apply(certificate: Certificate): Unit
}

object Consul {

  class ConsulException(message: String) extends RuntimeException(message)

  private case class LeafReply(CertPEM: String, PrivateKeyPEM: String)

  private case class Root(RootCert: String)
  private case class RootReply(Roots: Seq[Root])

  private case class AuthorizeRequest(Target: String, ClientCertURI: String, ClientCertSerial: String)
  private case class AuthorizeReply(Authorized: Boolean)

  private def certificateFromString(s: String) =
    CertificateFactory.getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(s.getBytes))

  private def privateKeyFromString(s: String) = {
    val reader = new StringReader(s)
    val parsedPEMObj = new PEMParser(reader).readObject()
    reader.close()
    new JcaPEMKeyConverter().getKeyPair(parsedPEMObj.asInstanceOf[PEMKeyPair]).getPrivate
  }

  def init(serviceName: String, agentAddress: String) = {
    Security.addProvider(new BouncyCastleProvider)
    new Consul(serviceName, agentAddress)
  }

  private implicit class EitherOps[E <: Throwable, T](val either: Either[E, T]) extends AnyVal {
    def asFuture: Future[T] = either match {
      case Left(e) => Future.exception(e)
      case Right(t) => Future.value(t)
    }
  }

}

class Consul private(
  serviceName: String,
  agentAddress: String,
  requestTimeout: Duration = Duration.fromSeconds(15))
  extends Closable with CloseAwaitably
{

  import Consul._

  private val logger = Logger()

  private val isRunning = new AtomicBoolean(false)
  private val timer = new JavaTimer(true)

  private val client = Http.client
    .withResponseClassifier(HttpResponseClassifier {
      case (_, res) if res.status != Status.Ok => ResponseClass.NonRetryableFailure
    })
    .newService(agentAddress, s"$serviceName-consul-client")

  override def close(deadline: Time): Future[Unit] = synchronized {
    isRunning.set(false)
    Future.Unit
  }

  private def request[A: Decoder, B](req: http.Request)(f: A => B): Future[B] = for {
    res <- client(req)
    decoded <- decode[A](res.getContentString()).asFuture
  } yield f(decoded)

  private def requestLeaf(): Future[(PrivateKey, Certificate)] = {
    val req = Request(s"/v1/agent/connect/ca/leaf/$serviceName")
    req.headerMap += "Host" -> agentAddress
    request(req) { r: LeafReply =>
      (privateKeyFromString(r.PrivateKeyPEM), certificateFromString(r.CertPEM))
    }
  }

  private def requestRoot(): Future[Certificate] = {
    val req = Request("/v1/agent/connect/ca/roots")
    req.headerMap += "Host" -> agentAddress
    request(req) { r: RootReply =>
      r.Roots.headOption
        .map(r => certificateFromString(r.RootCert))
        .getOrElse(throw new ConsulException("Root request returned no certificate"))
    }
  }

  def authorize(uri: String, serial: String): Future[Boolean] = {
    val req = Request(Method.Post, "/v1/agent/connect/authorize")
    val authReq = AuthorizeRequest(serviceName, uri, serial)
    req.content = Buf.Utf8(authReq.asJson.noSpaces)
    req.headerMap ++= Map(
      "Host" -> agentAddress,
      "Content-Type" -> "application/json",
      "Content-Length" -> req.content.length.toString)
    request[AuthorizeReply, Boolean](req)(_.Authorized)
  }

  def authorize(session: SSLSession): Future[Boolean] = {
    logger.debug(s"Start authorize - got ${session.getPeerCertificates.length} peer certificates")
    session.getPeerCertificates.collectFirst { case c: X509Certificate => c } match {
      case Some(c) =>
        val serial = c.getSerialNumber.toString(16).replaceAll("(?<=..)(..)", ":$1")
        logger.debug(s"Got authorize serial: $serial")
        val bcc = BCCertificate.getInstance(c.getEncoded)
        val extSAN = bcc.getTBSCertificate.getExtensions
          .getExtension(new ASN1ObjectIdentifier("2.5.29.17"))
        val firstSAN = extSAN.getParsedValue.toASN1Primitive.asInstanceOf[ASN1Sequence].getObjectAt(0)
        val uriASNObj = firstSAN.asInstanceOf[ASN1TaggedObject].getObject.asInstanceOf[ASN1OctetString]
        val uri = uriASNObj.getOctets.map(_.toChar).mkString
        logger.debug(s"Got authorize uri: $uri")
        authorize(uri, serial)
      case None =>
        Future.False
    }
  }

  def mkManagerFactories = {
    requestLeaf() join requestRoot() map {
      case ((privateKey, cert), rootCert) =>
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)

        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
        keyStore.load(null, null)

        val pwd = "".toCharArray

        val consulKeyStore: ConsulKeyStore = (privateKey, certificate) => {
          keyStore.setCertificateEntry("cert", certificate)
          keyStore.setKeyEntry("private-key", privateKey, pwd, Array(certificate))
        }

        consulKeyStore(privateKey, cert)

        kmf.init(keyStore, pwd)

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)

        val caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
        caKeyStore.load(null, null)

        val consulCAKeyStore: ConsulCAKeyStore = cert =>
          caKeyStore.setCertificateEntry("caCert-cert", cert)

        consulCAKeyStore(rootCert)

        tmf.init(caKeyStore)

        (kmf, consulKeyStore, tmf, consulCAKeyStore)
    }
  }

  def run(updateHandler: ((PrivateKey, Certificate, Certificate)) => Unit): Future[Unit] = synchronized {
    isRunning.set(true)
    def run_ : Future[Unit] = {
      if (isRunning.get())
        (requestLeaf() join requestRoot())
          .delayed(requestTimeout)(timer)
          .map { case ((pk, c), ca) => updateHandler((pk, c, ca)) }
          .before(run_)
      else Future.Done
    }
    run_
  }

}
