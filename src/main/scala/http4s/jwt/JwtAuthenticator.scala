package http4s.jwt

import cats.data.{Kleisli, OptionT}
import cats.instances.option._
import cats.syntax.alternative._
import cats.syntax.applicative._
import cats.syntax.flatMap._
import cats.syntax.option._
import cats.{Monad, MonadError}
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, HttpService, Request, Response, Status}
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

import scala.util.{Failure, Success}

trait JwtAuthenticator {

  import Config.jwtConfig._

  def generateToken(): String = {
    val claim = JwtClaim().expiresIn(expirationTime.toSeconds)
    Jwt.encode(claim, secret, JwtAlgorithm.HS256)
  }

  def jwtAuthenticate[F[_] : Monad](service: HttpService[F]): HttpService[F] = Kleisli { req: Request[F] =>
    val validateRequest = getCredentials[F] andThen getEncodedJwtToken andThen validate
    val response = validateRequest(req).map(_ => service(req))

    response.getOrElse(Response[F](status = Status.Unauthorized).pure[OptionT[F, ?]])
  }

  def extractJwtToken[F[_] : Monad : MonadError[?[_], Throwable]](req: Request[F]): F[String] =
      (getCredentials andThen getEncodedJwtToken).apply(req)
        .map(_.pure[F])
        .getOrElse(MonadError[F, Throwable].raiseError(new IllegalStateException("Missing JWT Token")))
        .flatMap(decodeToken.run)

  private def decodeToken[F[_] : MonadError[?[_], Throwable]]: Kleisli[F, String, String] = Kleisli { token =>
    Jwt.decode(token, secret, List(JwtAlgorithm.HS256)) match {
      case Success(decodedToken) => decodedToken.pure[F]
      case Failure(error) => MonadError[F, Throwable].raiseError(error)
    }
  }

  private def getCredentials[F[_]]: Kleisli[Option, Request[F], Credentials] = Kleisli { req =>
    req.headers.get(Authorization).map(_.credentials)
  }

  private def getEncodedJwtToken: Kleisli[Option, Credentials, String] = Kleisli {
    case Token(AuthScheme.Bearer, token) => token.some
    case _ => none[String]
  }

  private def validate: Kleisli[Option, String, Unit] = Kleisli { token =>
    Jwt.isValid(token, secret, List(JwtAlgorithm.HS256)).guard[Option]
  }

}
