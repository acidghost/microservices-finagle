package orders

import com.twitter.finagle.ssl.client.SslClientConfiguration
import com.twitter.finagle.ssl.{KeyCredentials, TrustCredentials}
import com.twitter.finagle.{Dtab, Thrift}
import com.twitter.util._
import consul.Consul
import thrift.users.UsersService


object Main extends App {

  Dtab.base = Dtab.base ++ Dtab.read("""
    | /s => /s#;
    | /s#/users => /s##/8081;
    | /s## => /$/inet/localhost;
    """.stripMargin)

  val consul = Consul.init("orders", "localhost:8500")

  val (keyManagerFactory, _, trustManagerFactory, _) =
    Await.result(consul.mkManagerFactories)

  val sslClientConfiguration = SslClientConfiguration(
    keyCredentials = KeyCredentials.KeyManagerFactory(keyManagerFactory),
    trustCredentials = TrustCredentials.TrustManagerFactory(trustManagerFactory)
  )

  val usersClient = Thrift.client
    .withTransport.tls(sslClientConfiguration)
    .build[UsersService.MethodPerEndpoint](
      "/s/users",
      "orders-users-client")

  val r = usersClient.find(42)
    .onSuccess { s =>
      println(s"[S] got $s")
    }
    .onFailure { t =>
      println(s"[E] got $t")
    }

  Await.ready(r)

}