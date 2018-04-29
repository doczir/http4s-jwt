package http4s.jwt

import cats.Id
import cats.effect.IO
import io.circe.parser._
import org.http4s.Credentials.Token
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, HttpService, Request, Status}
import org.scalatest.{EitherValues, Inside, Matchers, WordSpec}
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

class JwtAuthenticatorSpec extends WordSpec with Matchers with JwtAuthenticator with Inside with EitherValues {

  val idHttp4sDsl = Http4sDsl[Id]
  import idHttp4sDsl._

  trait ServiceScope {

    var wasCalled = false

    val dummyService: HttpService[Id] = HttpService[Id] {
      case _ =>
        wasCalled = true
        NoContent()
    }

  }

  "JwtAuthenticator" when {
    "using no jwt token" should {
      "return Unauthorized" in new ServiceScope {
        val request = Request[Id]()
        val authenticatedService = jwtAuthenticate(dummyService)
        val response = authenticatedService.orNotFound.run(request)

        response.status shouldEqual Status.Unauthorized
        wasCalled should not be true
      }
    }

    "using valid jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = generateToken()
        val request = Request[Id]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService)
        val response = authenticatedService.orNotFound.run(request)

        response.status shouldEqual Status.NoContent
        wasCalled shouldBe true
      }
    }

    "using wrong jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = Jwt.encode(JwtClaim())
        val request = Request[Id]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService)
        val response = authenticatedService.orNotFound.run(request)

        response.status shouldEqual Status.Unauthorized
        wasCalled shouldBe false
      }
    }
  }

  "JWT Token extractor" when {
    "given a valid jwt token" should {
      "return the extracted token" in {
        val token = generateToken()
        val request = Request[IO]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))

        val extractedToken = extractJwtToken[IO](request).unsafeRunSync()
        val decodedOriginalToken = Jwt.decode(token, Config.jwtConfig.secret, List(JwtAlgorithm.HS256)).get
        decodedOriginalToken shouldEqual extractedToken
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
