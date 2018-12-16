package users

import com.twitter.finagle.ssl.server.{SslServerConfiguration, SslServerSessionVerifier}
import com.twitter.finagle.ssl.{ClientAuth, KeyCredentials, TrustCredentials}
import com.twitter.finagle.thrift.RichServerParam
import com.twitter.finagle.{Address, Thrift}
import com.twitter.server.TwitterServer
import com.twitter.util.{Await, Duration, Future}
import consul.Consul
import javax.net.ssl.SSLSession
import thrift.users.UsersService


object Main extends TwitterServer {

  val service = new UsersService[Future] {
    override def find(id: Long): Future[String] = Future.value(s"Joe - $id")
  }


  override def defaultAdminPort: Int = 9081

  def main(): Unit = {
    val serviceName = "users"
    val finagledService = new UsersService.FinagledService(service, RichServerParam())

    val consul = Consul.init(serviceName, "localhost:8500")

    val (keyManagerFactory, keyStore, trustManagerFactory, caKeyStore) =
      Await.result(consul.mkManagerFactories)

    consul.run {
      case (pk, c, ce) =>
        keyStore(pk, c)
        caKeyStore(ce)
    }.onFailure(exitOnError)

    val sslServerConfiguration = SslServerConfiguration(
      clientAuth = ClientAuth.Needed,
      keyCredentials = KeyCredentials.KeyManagerFactory(keyManagerFactory),
      trustCredentials = TrustCredentials.TrustManagerFactory(trustManagerFactory)
    )

    val sslServerSessionVerifier = new SslServerSessionVerifier {
      val timeout = Duration.fromSeconds(5)
      override def apply(address: Address, config: SslServerConfiguration, session: SSLSession): Boolean = {
        Await.result(consul.authorize(session), timeout)
      }
    }

    val server = Thrift.server
      .withLabel(serviceName)
      .withTransport.tls(sslServerConfiguration, sslServerSessionVerifier)
      .serveAndAnnounce(serviceName, ":8081", finagledService)

    onExit {
      server.close().onSuccess(_ => info("Server shut down"))
      consul.close().onSuccess(_ => info("Consul shut down"))
    }

    Await.ready(server)
  }

}

