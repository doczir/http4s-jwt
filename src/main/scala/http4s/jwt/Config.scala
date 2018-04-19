package http4s.jwt

import pureconfig.loadConfigOrThrow

import scala.concurrent.duration.Duration


trait Config {

  case class JwtConfig(expirationTime: Duration, secret: String)

  val jwtConfig: JwtConfig = loadConfigOrThrow[JwtConfig]("jwt-config")
}

object Config extends Config