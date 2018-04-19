package http4s.jwt

import cats.data.{Kleisli, OptionT}
import cats.syntax.applicative._
import cats.effect.IO
import org.http4s.{HttpService, Request, Response, Status}
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

trait JwtAuthenticator {

  import Config._

  def generateToken(): String = {
    val claim = JwtClaim().expiresIn(jwtConfig.expirationTime.toSeconds)
    Jwt.encode(claim, jwtConfig.secret, JwtAlgorithm.HS256)
  }

  def jwtAuthenticate(service: HttpService[IO]): HttpService[IO] = Kleisli { _: Request[IO] =>
    service == service // avoid compile error
    Response[IO](status = Status.Unauthorized).pure[OptionT[IO, ?]]
  }

}
