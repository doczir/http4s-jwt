package http4s.jwt

import cats.Id
import cats.effect.IO
import cats.instances.either._
import io.circe.{Decoder, Json}
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

  class DummyService {
    var called = false

    val service: HttpService[Id] = HttpService[Id] {
      case _ =>
        called = true
        NoContent()
    }
  }

  trait ServiceScope {

    val dummyService = new DummyService()

  }

  "JwtAuthenticator" when {
    "using no jwt token" should {
      "return Unauthorized" in new ServiceScope {
        val request = Request[Id]()
        val authenticatedService = jwtAuthenticate(dummyService.service)
        val response = authenticatedService.orNotFound.run(request)

        response.status should === (Status.Unauthorized)
        dummyService should not be 'called
      }
    }

    "using valid jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = generateToken()
        val request = Request[Id]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService.service)
        val response = authenticatedService.orNotFound.run(request)

        response.status should === (Status.NoContent)
        dummyService shouldBe 'called
      }
    }

    "using wrong jwt token" should {
      "return NoContent" in new ServiceScope {
        val token = Jwt.encode(JwtClaim())
        val request = Request[Id]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))
        val authenticatedService = jwtAuthenticate(dummyService.service)
        val response = authenticatedService.orNotFound.run(request)

        response.status should === (Status.Unauthorized)
        dummyService should not be 'called
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

        decodedOriginalToken should === (extractedToken)
      }

      "using no jwt token" should {
        "returns a failed context" in {
          val request = Request[Either[Throwable, ?]]()

          extractJwtToken(request).left.value shouldBe a[JwtAuthenticationError]
        }
      }

      "using wrong jwt token" should {
        "returns a failed context" in {
          val token = Jwt.encode(JwtClaim())
          val request = Request[Either[Throwable, ?]]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))

          extractJwtToken(request).left.value shouldBe a[JwtAuthenticationError]
        }
      }
    }
  }

  "JWT Token generator" when {
    "called" should {
      "generate a valid jwt token" in {
        val token = generateToken()

        inside(Jwt.decode(token, Config.jwtConfig.secret, List(JwtAlgorithm.HS256)).toEither.flatMap(parse)) {
          case Right(tokenJson) =>
            shouldHaveKey[Long](tokenJson, "exp")
        }
      }
    }
  }

  private def shouldHaveKey[T: Decoder](tokenJson: Json, exp: String) = {
    tokenJson.hcursor.downField(exp).as[T].right.value
  }
}
