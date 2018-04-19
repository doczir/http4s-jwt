package http4s.jwt

import cats.effect.IO
import io.circe.parser._
import org.http4s.dsl.io._
import org.http4s.{HttpService, Request, Status}
import org.scalatest.{EitherValues, Inside, Matchers, WordSpec}
import pdi.jwt.{Jwt, JwtAlgorithm}

class JwtAuthenticatorSpec extends WordSpec with Matchers with JwtAuthenticator with Inside with EitherValues {

  trait ServiceScope {

    var wasCalled = false

    val dummyService: HttpService[IO] = HttpService[IO] {
      case _ =>
        wasCalled = true
        NoContent()
    }

  }

  "JwtAuthenticator" when {
    "using no jwt token" should {
      "return Unauthorized" in new ServiceScope {
        val request              = Request[IO]()
        val authenticatedService = jwtAuthenticate(dummyService)
        val response             = authenticatedService.orNotFound.run(request).unsafeRunSync()

        response.status shouldEqual Status.Unauthorized
        wasCalled should not be true
      }
    }
  }

  "JWT Token generator" when {
    "called" should {
      "generate a valid jwt token" in {
        val token = generateToken()

        inside(Jwt.decode(token, Config.jwtConfig.secret, List(JwtAlgorithm.HS256)).toEither.flatMap(parse)) {
          case Right(tokenJson) =>
            tokenJson.hcursor.downField("exp").as[Long].right.value
        }
      }
    }
  }

}
