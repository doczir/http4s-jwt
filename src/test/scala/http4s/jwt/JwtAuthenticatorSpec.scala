package http4s.jwt

import cats.effect.IO
import io.circe.parser._
import org.http4s.Credentials.Token
import org.http4s.dsl.io._
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, HttpService, Request, Status}
import org.scalatest.{EitherValues, Inside, Matchers, WordSpec}
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

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

    "using valid jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = generateToken()
        val request              = Request[IO]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService)
        val response             = authenticatedService.orNotFound.run(request).unsafeRunSync()

        response.status shouldEqual Status.NoContent
        wasCalled shouldBe true
      }
    }

    "using wrong jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = Jwt.encode(JwtClaim())
        val request              = Request[IO]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService)
        val response             = authenticatedService.orNotFound.run(request).unsafeRunSync()

        response.status shouldEqual Status.Unauthorized
        wasCalled shouldBe false
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
