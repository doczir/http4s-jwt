package http4s.jwt

import cats.data.{Kleisli, OptionT}
import cats.syntax.applicative._
import cats.effect.IO
import org.http4s.{HttpService, Request, Response, Status}

trait JwtAuthenticator {

  def jwtAuthenticate(service: HttpService[IO]): HttpService[IO] = Kleisli { _: Request[IO] =>
    service == service // avoid compile error
    Response[IO](status = Status.Unauthorized).pure[OptionT[IO, ?]]
  }

}
