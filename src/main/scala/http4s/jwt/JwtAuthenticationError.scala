package http4s.jwt

case class JwtAuthenticationError(message: String = "", cause: Throwable = null) extends Exception(message, cause)
