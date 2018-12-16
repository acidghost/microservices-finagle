ThisBuild / scalaVersion := "2.12.8"
ThisBuild / organization := "io.github.acidghost"


val versions = new {
  val twitterStack = "18.11.0"
  val libthrift = "0.10.0"
  val logback = "1.2.3"
  val circe = "0.10.1"
}

val twitterServer = Seq(
  "com.twitter" %% "twitter-server" % versions.twitterStack,
  "com.twitter" %% "twitter-server-logback-classic" % versions.twitterStack
)

val thrift = Seq(
  "com.twitter" %% "finagle-thrift" % versions.twitterStack exclude("com.twitter", "libthrift"),
  "com.twitter" %% "scrooge-core" % versions.twitterStack exclude("com.twitter", "libthrift"),
  "org.apache.thrift" % "libthrift" % versions.libthrift
)

val circe = Seq(
  "io.circe" %% "circe-core",
  "io.circe" %% "circe-generic",
  "io.circe" %% "circe-parser"
).map(_ % versions.circe)

val serviceLibs = twitterServer ++ Seq(
  "ch.qos.logback" % "logback-classic" % versions.logback,
  "com.twitter" %% "finagle-stats" % versions.twitterStack
)


lazy val users = (project in file("users"))
  .settings(
    name := "users",
    libraryDependencies ++= serviceLibs
  )
  .dependsOn(thriftApi, consul)

lazy val orders = (project in file("orders"))
  .settings(
    name := "orders",
    libraryDependencies ++= serviceLibs
  )
  .dependsOn(thriftApi, consul)

lazy val thriftApi = (project in file("thrift-api"))
  .settings(
    name := "thrift-api",
    libraryDependencies ++= thrift
  )

lazy val consul = (project in file("consul"))
  .settings(
    name := "consul",
    libraryDependencies ++= circe ++ Seq(
      "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
      "org.bouncycastle" % "bcpkix-jdk15on" % "1.60",
      "com.twitter" %% "finagle-http" % versions.twitterStack
    )
  )
