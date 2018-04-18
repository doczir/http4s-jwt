package http4s.jwt

import cats.effect.IO
import org.http4s.{HttpService, Request, Status}
import org.http4s.dsl.io._
import org.scalatest.{Matchers, WordSpec}

class JwtAuthenticatorSpec extends WordSpec with Matchers with JwtAuthenticator{

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
        val request = Request[IO]()

        val authenticatedService = jwtAuthenticate(dummyService)

        val response = authenticatedService.orNotFound.run(request).unsafeRunSync()

        response.status shouldEqual Status.Unauthorized
        wasCalled should not be true
      }
    }
  }



}
