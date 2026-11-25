// =============================================================================
//  Mini Proyecto: Higher Order Functions en Criptografía
//  Programación Funcional y Reactiva - Scala 3
//
//  Motor de cifrado que recibe la función de transformación como parámetro.
//  Estrategias implementadas: Cifrado César (desplazamiento) y Cifrado XOR.
// =============================================================================

import scala.util.{Try, Success, Failure}

// -----------------------------------------------------------------------------
// 1. Tipos y excepciones del dominio
// -----------------------------------------------------------------------------

/** Una función de cifrado transforma un carácter usando una clave entera. */
type FuncionCifrado = (Char, Int) => Char

/** Errores propios del motor (todos son excepciones para poder capturarlos con Try). */
final case class MensajeInvalidoException(msg: String)     extends IllegalArgumentException(msg)
final case class ClaveInvalidaException(msg: String)       extends IllegalArgumentException(msg)
final case class CaracterNoSoportadoException(msg: String) extends IllegalArgumentException(msg)

// -----------------------------------------------------------------------------
// 2. Motor de cifrado (función de orden superior)
// -----------------------------------------------------------------------------

/** Aplica `funcion` a cada carácter de `mensaje` usando `map`.
  *
  * Es una función de orden superior: recibe otra función como parámetro.
  * Nunca lanza excepciones hacia afuera; el resultado queda envuelto en `Try`:
  *   - `Success(textoTransformado)` si todo salió bien.
  *   - `Failure(error)` si el mensaje, la clave o algún carácter no son válidos.
  */
def procesarMensaje(mensaje: String, clave: Int, funcion: FuncionCifrado): Try[String] =
  Try {
    if mensaje == null then throw MensajeInvalidoException("El mensaje es nulo")
    if mensaje.trim.isEmpty then throw MensajeInvalidoException("El mensaje está vacío")
    mensaje.map(c => funcion(c, clave)) // transformación inmutable con map
  }

// -----------------------------------------------------------------------------
// 3. Estrategias de cifrado (funciones puras que se pasan como argumento)
// -----------------------------------------------------------------------------

object Cesar:
  val TamanoAlfabeto = 26
  val ClaveMaxima    = 25 // una clave fuera de [-25, 25] se considera inválida

  /** E(x, k) = (pos(x) + k) mod 26. Soporta letras A-Z / a-z; el espacio se conserva. */
  val cifrar: FuncionCifrado = (c, k) =>
    if k.abs > ClaveMaxima then
      throw ClaveInvalidaException(s"Clave César fuera de rango: $k (permitido: -$ClaveMaxima..$ClaveMaxima)")
    else if c == ' ' then c
    else if c.isLetter && c.toUpper >= 'A' && c.toUpper <= 'Z' then
      val base = if c.isUpper then 'A' else 'a'
      val pos  = c - base
      // floorMod evita índices negativos cuando la clave es negativa (descifrado)
      (base + Math.floorMod(pos + k, TamanoAlfabeto)).toChar
    else
      throw CaracterNoSoportadoException(s"Carácter no soportado por César: '$c'")

  /** Lógica inversa: descifrar es cifrar con la clave de signo opuesto. */
  val descifrar: FuncionCifrado = (c, k) => cifrar(c, -k)

object Xor:
  val ClaveMaxima = 127 // la clave debe ser un valor de 7 bits (ASCII)

  /** E(x, k) = ASCII(x) ⊕ k, usando el operador ^ dentro de la lambda. */
  val cifrar: FuncionCifrado = (c, k) =>
    if k < 0 || k > ClaveMaxima then
      throw ClaveInvalidaException(s"Clave XOR fuera de rango: $k (permitido: 0..$ClaveMaxima)")
    else if c.toInt > 127 then
      throw CaracterNoSoportadoException(s"Carácter no ASCII: '$c' (código ${c.toInt})")
    else (c ^ k).toChar

// -----------------------------------------------------------------------------
// 4. Utilidades de presentación
// -----------------------------------------------------------------------------

/** Convierte el Try en un texto legible usando Success / Failure. */
def mostrar(titulo: String, resultado: Try[String]): Unit =
  resultado match
    case Success(texto) => println(f"  $titulo%-38s -> Success(\"$texto\")")
    case Failure(error) => println(f"  $titulo%-38s -> Failure(${error.getClass.getSimpleName}: ${error.getMessage})")

def binario(n: Int): String =
  val b = String.format("%8s", n.toBinaryString).replace(' ', '0')
  s"${b.take(4)} ${b.drop(4)}"

def separador(titulo: String): Unit =
  println()
  println("=" * 70)
  println(s"  $titulo")
  println("=" * 70)

// -----------------------------------------------------------------------------
// 5. Programa principal: pruebas de cifrado, descifrado y manejo de errores
// -----------------------------------------------------------------------------

@main def ejecutar(): Unit =

  // ---------- Ejemplo 1: César paso a paso ("AD", k = 1) ----------
  separador("EJEMPLO 1: César paso a paso  (mensaje = \"AD\", k = 1)")
  "AD".foreach { c =>
    val pos = c - 'A'
    println(s"  Letra '$c' ($pos): ($pos + 1) mod 26 = ${(pos + 1) % 26} -> '${Cesar.cifrar(c, 1)}'")
  }
  mostrar("procesarMensaje(\"AD\", 1, Cesar.cifrar)", procesarMensaje("AD", 1, Cesar.cifrar))

  // ---------- Caso César: FUNCIONAL con k = 3 ----------
  separador("CASO CÉSAR  (mensaje = \"FUNCIONAL\", k = 3)")
  val cifradoCesar = procesarMensaje("FUNCIONAL", 3, Cesar.cifrar)
  mostrar("Cifrar FUNCIONAL con k = 3", cifradoCesar)

  // Descifrado 1: misma función con clave -3
  val descifradoNeg = cifradoCesar.flatMap(t => procesarMensaje(t, -3, Cesar.cifrar))
  mostrar("Descifrar con k = -3", descifradoNeg)

  // Descifrado 2: función inversa (lógica inversa) con k = 3
  val descifradoInv = cifradoCesar.flatMap(t => procesarMensaje(t, 3, Cesar.descifrar))
  mostrar("Descifrar con Cesar.descifrar, k = 3", descifradoInv)
  println(s"  ¿Se recuperó el original? ${descifradoNeg == Success("FUNCIONAL")}")

  // ---------- Ejemplo 2 / Caso XOR: scala con k = 5 ----------
  separador("CASO XOR  (mensaje = \"scala\", k = 5)")
  println("  Carácter | ASCII | Binario   | XOR 5 (cálculo) | Binario   | Res. ASCII | Cifrado")
  println("  ---------+-------+-----------+-----------------+-----------+------------+--------")
  "scala".foreach { c =>
    val r = c ^ 5
    println(f"  $c%-8s | ${c.toInt}%5d | ${binario(c.toInt)} | ${c.toInt}%5d ^ 5       | ${binario(r)} | $r%10d | ${r.toChar}")
  }

  // La lambda se escribe en línea usando el operador ^ (caret)
  val lambdaXor: FuncionCifrado = (c, k) => (c ^ k).toChar
  val cifradoXor = procesarMensaje("scala", 5, lambdaXor)
  mostrar("Cifrar scala con k = 5 (lambda ^)", cifradoXor)

  // Aplicar la MISMA función con la MISMA clave devuelve el original
  val descifradoXor = cifradoXor.flatMap(t => procesarMensaje(t, 5, lambdaXor))
  mostrar("Volver a aplicar XOR con k = 5", descifradoXor)
  mostrar("Con la versión validada Xor.cifrar", procesarMensaje("scala", 5, Xor.cifrar))
  println(s"  ¿Se recuperó el original? ${descifradoXor == Success("scala")}")

  // ---------- Manejo de errores ----------
  separador("MANEJO DE ERRORES (fallos forzados, capturados con Try)")
  mostrar("Mensaje vacío \"\"", procesarMensaje("", 3, Cesar.cifrar))
  mostrar("Mensaje solo espacios \"   \"", procesarMensaje("   ", 3, Cesar.cifrar))
  mostrar("Mensaje nulo (null)", procesarMensaje(null, 3, Cesar.cifrar))
  mostrar("César con clave excesiva k = 1000", procesarMensaje("FUNCIONAL", 1000, Cesar.cifrar))
  mostrar("XOR con clave excesiva k = 99999", procesarMensaje("scala", 99999, Xor.cifrar))
  mostrar("XOR con clave negativa k = -5", procesarMensaje("scala", -5, Xor.cifrar))
  mostrar("César con carácter especial \"HOLA!\"", procesarMensaje("HOLA!", 3, Cesar.cifrar))
  mostrar("César con dígitos \"SCALA3\"", procesarMensaje("SCALA3", 3, Cesar.cifrar))
  mostrar("César con 'Ñ' \"ESPAÑA\"", procesarMensaje("ESPAÑA", 3, Cesar.cifrar))
  mostrar("XOR con carácter no ASCII \"año€\"", procesarMensaje("año€", 5, Xor.cifrar))

  // Recuperación elegante: valor por defecto con getOrElse / recover
  val seguro = procesarMensaje("HOLA!", 3, Cesar.cifrar).recover {
    case e: CaracterNoSoportadoException => s"[no se pudo cifrar: ${e.getMessage}]"
  }
  mostrar("recover sobre \"HOLA!\"", seguro)
  println()
  println("  Fin de la ejecución: ningún error detuvo el programa.")
