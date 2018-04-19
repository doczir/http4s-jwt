package http4s.jwt

import cats.data.{Kleisli, OptionT}
import cats.effect.IO
import cats.instances.option._
import cats.syntax.alternative._
import cats.syntax.applicative._
import cats.syntax.option._
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, HttpService, Request, Response, Status}
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

trait JwtAuthenticator {

  import Config.jwtConfig._

  def generateToken(): String = {
    val claim = JwtClaim().expiresIn(expirationTime.toSeconds)
    Jwt.encode(claim, secret, JwtAlgorithm.HS256)
  }

  def jwtAuthenticate(service: HttpService[IO]): HttpService[IO] = Kleisli { req: Request[IO] =>
    val response = for {
      credentials <- getCredentials(req)
      token       <- getJwtToken(credentials)
      _           <- validate(token)
    } yield service(req)

    response.getOrElse(Response[IO](status = Status.Unauthorized).pure[OptionT[IO, ?]])
  }

  private def getCredentials: Request[IO] => Option[Credentials] =
    req => req.headers.get(Authorization).map(_.credentials)

  private def getJwtToken: Credentials => Option[String] = {
    case Token(AuthScheme.Bearer, token) => token.some
    case _                               => none[String]
  }

  private def validate: String => Option[Unit] =
    token => Jwt.isValid(token, secret, List(JwtAlgorithm.HS256)).guard[Option]

}
