# 🔐 Mini Proyecto: Higher Order Functions en Criptografía

**Curso:** Programación Funcional y Reactiva
**Lenguaje:** Scala 3 (3.3.4)
**Autor:** Patricio Rivas

Motor de cifrado escrito con un estilo funcional: la estrategia de cifrado **no está fija**, se pasa como **función parámetro** a una función de orden superior (`procesarMensaje`). Se implementan dos estrategias: **Cifrado César** y **Cifrado XOR**, con manejo de errores mediante `Try / Success / Failure`.

---

## 📑 Tabla de contenidos

1. [Objetivos](#-objetivos)
2. [Estructura del repositorio](#-estructura-del-repositorio)
3. [Cómo ejecutar](#️-cómo-ejecutar)
4. [Desarrollo](#-desarrollo)
   - [4.1 Tipos y excepciones](#41-tipos-y-excepciones-del-dominio)
   - [4.2 Función de orden superior `procesarMensaje`](#42-función-de-orden-superior-procesarmensaje)
   - [4.3 Estrategia César](#43-estrategia-1-cifrado-césar)
   - [4.4 Estrategia XOR](#44-estrategia-2-cifrado-xor)
5. [Pruebas y resultados](#-pruebas-y-resultados)
   - [5.1 Ejemplo César "AD"](#51-ejemplo-1-césar-paso-a-paso-ad-k--1)
   - [5.2 Caso César "FUNCIONAL"](#52-caso-césar-funcional-con-k--3)
   - [5.3 Caso XOR "scala"](#53-caso-xor-scala-con-k--5)
   - [5.4 Manejo de errores](#54-manejo-de-errores)
6. [Preguntas para reflexionar](#-preguntas-para-reflexionar)
7. [Conclusiones](#-conclusiones)

---

## 🎯 Objetivos

- Aplicar funciones de orden superior (*Higher Order Functions*).
- Usar funciones como parámetros para definir estrategias de cifrado dinámicas.
- Transformar colecciones inmutables con `map`.
- Validar datos y manejar excepciones de forma elegante con `Try`.

---

## 📁 Estructura del repositorio

```
MiniProyecto/
├── README.md                     # Documentación (esta wiki)
├── build.sbt                     # Configuración de sbt (Scala 3.3.4)
├── project/
│   └── build.properties          # Versión de sbt
├── src/
│   └── main/
│       └── scala/
│           └── MotorCifrado.scala  # Código fuente completo
├── salida_ejecucion.txt          # Salida completa de la ejecución
└── capturas/                     # Capturas de pantalla de la ejecución
```

---

## ▶️ Cómo ejecutar

Con **sbt**:

```bash
sbt run
```

O con **Scala CLI** (sin proyecto sbt):

```bash
scala-cli run src/main/scala/MotorCifrado.scala
```

> 💡 En Windows, si los acentos aparecen como `?`, ejecutar antes `chcp 65001` en la consola.

---

## 🧠 Desarrollo

### 4.1 Tipos y excepciones del dominio

Se define un **alias de tipo** para la firma de toda función de cifrado `(Char, Int) => Char`, y tres excepciones propias para distinguir cada tipo de error.

```scala
import scala.util.{Try, Success, Failure}

/** Una función de cifrado transforma un carácter usando una clave entera. */
type FuncionCifrado = (Char, Int) => Char

final case class MensajeInvalidoException(msg: String)     extends IllegalArgumentException(msg)
final case class ClaveInvalidaException(msg: String)       extends IllegalArgumentException(msg)
final case class CaracterNoSoportadoException(msg: String) extends IllegalArgumentException(msg)
```

### 4.2 Función de orden superior `procesarMensaje`

Es el **motor de cifrado**. Recibe el mensaje, la clave y **la función de cifrado como parámetro**. Aplica la función a cada carácter con `map` y envuelve todo en un `Try`, de modo que **nunca lanza excepciones hacia afuera**: devuelve `Success(texto)` o `Failure(error)`.

```scala
def procesarMensaje(mensaje: String, clave: Int, funcion: FuncionCifrado): Try[String] =
  Try {
    if mensaje == null then throw MensajeInvalidoException("El mensaje es nulo")
    if mensaje.trim.isEmpty then throw MensajeInvalidoException("El mensaje está vacío")
    mensaje.map(c => funcion(c, clave)) // transformación inmutable con map
  }
```

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `mensaje` | `String` | Texto a cifrar / descifrar |
| `clave` | `Int` | Clave numérica |
| `funcion` | `(Char, Int) => Char` | Estrategia de cifrado (función como parámetro) |
| **retorno** | `Try[String]` | `Success` con el resultado o `Failure` con el error |

Para mostrar el resultado se usa *pattern matching* sobre `Success` / `Failure`:

```scala
def mostrar(titulo: String, resultado: Try[String]): Unit =
  resultado match
    case Success(texto) => println(f"  $titulo%-38s -> Success(\"$texto\")")
    case Failure(error) => println(f"  $titulo%-38s -> Failure(${error.getClass.getSimpleName}: ${error.getMessage})")
```

### 4.3 Estrategia 1: Cifrado César

$$E(x, k) = (pos(x) + k) \bmod 26$$

- Solo acepta letras `A-Z` / `a-z` (respeta mayúsculas/minúsculas) y conserva los espacios.
- La clave debe estar en el rango `[-25, 25]`; fuera de él se considera inválida.
- Se usa `Math.floorMod` para que las claves negativas (descifrado) no generen índices negativos.
- **Descifrar** = cifrar con la clave de signo opuesto (`-k`).

```scala
object Cesar:
  val TamanoAlfabeto = 26
  val ClaveMaxima    = 25

  val cifrar: FuncionCifrado = (c, k) =>
    if k.abs > ClaveMaxima then
      throw ClaveInvalidaException(s"Clave César fuera de rango: $k (permitido: -$ClaveMaxima..$ClaveMaxima)")
    else if c == ' ' then c
    else if c.isLetter && c.toUpper >= 'A' && c.toUpper <= 'Z' then
      val base = if c.isUpper then 'A' else 'a'
      val pos  = c - base
      (base + Math.floorMod(pos + k, TamanoAlfabeto)).toChar
    else
      throw CaracterNoSoportadoException(s"Carácter no soportado por César: '$c'")

  /** Lógica inversa: descifrar es cifrar con la clave de signo opuesto. */
  val descifrar: FuncionCifrado = (c, k) => cifrar(c, -k)
```

### 4.4 Estrategia 2: Cifrado XOR

$$E(x, k) = ASCII(x) \oplus k$$

- Usa el operador `^` (caret) a nivel de bits.
- La clave debe estar en `[0, 127]` y el carácter debe ser ASCII.
- Aplicar dos veces la misma operación con la misma clave devuelve el original.

```scala
object Xor:
  val ClaveMaxima = 127

  val cifrar: FuncionCifrado = (c, k) =>
    if k < 0 || k > ClaveMaxima then
      throw ClaveInvalidaException(s"Clave XOR fuera de rango: $k (permitido: 0..$ClaveMaxima)")
    else if c.toInt > 127 then
      throw CaracterNoSoportadoException(s"Carácter no ASCII: '$c' (código ${c.toInt})")
    else (c ^ k).toChar
```

Además, tal como pide el enunciado, en las pruebas se pasa una **lambda en línea** con `^`:

```scala
val lambdaXor: FuncionCifrado = (c, k) => (c ^ k).toChar
```

---

## 🧪 Pruebas y resultados

> Todas las salidas mostradas a continuación son la **salida real** de ejecutar el programa (`sbt run`). La salida completa está en [`salida_ejecucion.txt`](salida_ejecucion.txt).

### 5.1 Ejemplo 1: César paso a paso ("AD", k = 1)

```scala
"AD".foreach { c =>
  val pos = c - 'A'
  println(s"  Letra '$c' ($pos): ($pos + 1) mod 26 = ${(pos + 1) % 26} -> '${Cesar.cifrar(c, 1)}'")
}
mostrar("procesarMensaje(\"AD\", 1, Cesar.cifrar)", procesarMensaje("AD", 1, Cesar.cifrar))
```

**Salida:**

```text
======================================================================
  EJEMPLO 1: César paso a paso  (mensaje = "AD", k = 1)
======================================================================
  Letra 'A' (0): (0 + 1) mod 26 = 1 -> 'B'
  Letra 'D' (3): (3 + 1) mod 26 = 4 -> 'E'
  procesarMensaje("AD", 1, Cesar.cifrar) -> Success("BE")
```

<!-- 📸 Captura: reemplazar por la imagen tomada al ejecutar -->
![Ejemplo César AD](capturas/01_ejemplo_cesar.png)

### 5.2 Caso César: "FUNCIONAL" con k = 3

Se cifra y luego se descifra de **dos formas**: pasando la clave `-3` a la misma función, y pasando la función inversa `Cesar.descifrar`. Se encadenan con `flatMap` para propagar un posible `Failure`.

```scala
val cifradoCesar = procesarMensaje("FUNCIONAL", 3, Cesar.cifrar)
mostrar("Cifrar FUNCIONAL con k = 3", cifradoCesar)

// Descifrado 1: misma función con clave -3
val descifradoNeg = cifradoCesar.flatMap(t => procesarMensaje(t, -3, Cesar.cifrar))
mostrar("Descifrar con k = -3", descifradoNeg)

// Descifrado 2: función inversa (lógica inversa) con k = 3
val descifradoInv = cifradoCesar.flatMap(t => procesarMensaje(t, 3, Cesar.descifrar))
mostrar("Descifrar con Cesar.descifrar, k = 3", descifradoInv)
println(s"  ¿Se recuperó el original? ${descifradoNeg == Success("FUNCIONAL")}")
```

**Salida:**

```text
======================================================================
  CASO CÉSAR  (mensaje = "FUNCIONAL", k = 3)
======================================================================
  Cifrar FUNCIONAL con k = 3             -> Success("IXQFLRQDO")
  Descifrar con k = -3                   -> Success("FUNCIONAL")
  Descifrar con Cesar.descifrar, k = 3   -> Success("FUNCIONAL")
  ¿Se recuperó el original? true
```

| Letra | pos | (pos + 3) mod 26 | Cifrado |
|:-----:|:---:|:----------------:|:-------:|
| F | 5  | 8  | I |
| U | 20 | 23 | X |
| N | 13 | 16 | Q |
| C | 2  | 5  | F |
| I | 8  | 11 | L |
| O | 14 | 17 | R |
| N | 13 | 16 | Q |
| A | 0  | 3  | D |
| L | 11 | 14 | O |

**Resultado:** `FUNCIONAL` → `IXQFLRQDO` → `FUNCIONAL` ✅

<!-- 📸 Captura -->
![Caso César FUNCIONAL](capturas/02_caso_cesar.png)

### 5.3 Caso XOR: "scala" con k = 5

```scala
// La lambda se escribe en línea usando el operador ^ (caret)
val lambdaXor: FuncionCifrado = (c, k) => (c ^ k).toChar
val cifradoXor = procesarMensaje("scala", 5, lambdaXor)
mostrar("Cifrar scala con k = 5 (lambda ^)", cifradoXor)

// Aplicar la MISMA función con la MISMA clave devuelve el original
val descifradoXor = cifradoXor.flatMap(t => procesarMensaje(t, 5, lambdaXor))
mostrar("Volver a aplicar XOR con k = 5", descifradoXor)
mostrar("Con la versión validada Xor.cifrar", procesarMensaje("scala", 5, Xor.cifrar))
println(s"  ¿Se recuperó el original? ${descifradoXor == Success("scala")}")
```

**Salida:**

```text
======================================================================
  CASO XOR  (mensaje = "scala", k = 5)
======================================================================
  Carácter | ASCII | Binario   | XOR 5 (cálculo) | Binario   | Res. ASCII | Cifrado
  ---------+-------+-----------+-----------------+-----------+------------+--------
  s        |   115 | 0111 0011 |   115 ^ 5       | 0111 0110 |        118 | v
  c        |    99 | 0110 0011 |    99 ^ 5       | 0110 0110 |        102 | f
  a        |    97 | 0110 0001 |    97 ^ 5       | 0110 0100 |        100 | d
  l        |   108 | 0110 1100 |   108 ^ 5       | 0110 1001 |        105 | i
  a        |    97 | 0110 0001 |    97 ^ 5       | 0110 0100 |        100 | d
  Cifrar scala con k = 5 (lambda ^)      -> Success("vfdid")
  Volver a aplicar XOR con k = 5         -> Success("scala")
  Con la versión validada Xor.cifrar     -> Success("vfdid")
  ¿Se recuperó el original? true
```

**Resultado:** `scala` → `vfdid` → `scala` ✅

<!-- 📸 Captura -->
![Caso XOR scala](capturas/03_caso_xor.png)

### 5.4 Manejo de errores

Se fuerzan fallos para demostrar la robustez: mensajes vacíos o nulos, claves excesivamente grandes o negativas, y caracteres no soportados. **Ningún error detiene el programa**: todos quedan capturados como `Failure`. Al final se usa `recover` para convertir un fallo en un valor por defecto.

```scala
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

// Recuperación elegante: valor por defecto con recover
val seguro = procesarMensaje("HOLA!", 3, Cesar.cifrar).recover {
  case e: CaracterNoSoportadoException => s"[no se pudo cifrar: ${e.getMessage}]"
}
mostrar("recover sobre \"HOLA!\"", seguro)
```

**Salida:**

```text
======================================================================
  MANEJO DE ERRORES (fallos forzados, capturados con Try)
======================================================================
  Mensaje vacío ""                       -> Failure(MensajeInvalidoException: El mensaje está vacío)
  Mensaje solo espacios "   "            -> Failure(MensajeInvalidoException: El mensaje está vacío)
  Mensaje nulo (null)                    -> Failure(MensajeInvalidoException: El mensaje es nulo)
  César con clave excesiva k = 1000      -> Failure(ClaveInvalidaException: Clave César fuera de rango: 1000 (permitido: -25..25))
  XOR con clave excesiva k = 99999       -> Failure(ClaveInvalidaException: Clave XOR fuera de rango: 99999 (permitido: 0..127))
  XOR con clave negativa k = -5          -> Failure(ClaveInvalidaException: Clave XOR fuera de rango: -5 (permitido: 0..127))
  César con carácter especial "HOLA!"    -> Failure(CaracterNoSoportadoException: Carácter no soportado por César: '!')
  César con dígitos "SCALA3"             -> Failure(CaracterNoSoportadoException: Carácter no soportado por César: '3')
  César con 'Ñ' "ESPAÑA"                 -> Failure(CaracterNoSoportadoException: Carácter no soportado por César: 'Ñ')
  XOR con carácter no ASCII "año€"       -> Failure(CaracterNoSoportadoException: Carácter no ASCII: 'ñ' (código 241))
  recover sobre "HOLA!"                  -> Success("[no se pudo cifrar: Carácter no soportado por César: '!']")

  Fin de la ejecución: ningún error detuvo el programa.
```

| Caso | Tipo de error | Excepción capturada |
|------|---------------|---------------------|
| `""`, `"   "` | Cadena vacía | `MensajeInvalidoException` |
| `null` | Cadena nula | `MensajeInvalidoException` |
| César `k = 1000` | Clave inválida (muy grande) | `ClaveInvalidaException` |
| XOR `k = 99999`, `k = -5` | Clave inválida | `ClaveInvalidaException` |
| `"HOLA!"`, `"SCALA3"`, `"ESPAÑA"` | Carácter no soportado por César | `CaracterNoSoportadoException` |
| `"año€"` | Carácter no ASCII en XOR | `CaracterNoSoportadoException` |

<!-- 📸 Captura -->
![Manejo de errores](capturas/04_manejo_errores.png)

---

## 💭 Preguntas para reflexionar

### ¿Por qué el método XOR es su propia función inversa usando el mismo operador `^`, mientras que el César requiere invertir el signo de la clave?

Porque XOR cumple dos propiedades: `k ⊕ k = 0` y `x ⊕ 0 = x`. Al aplicar dos veces la misma clave: `(x ⊕ k) ⊕ k = x ⊕ (k ⊕ k) = x ⊕ 0 = x`. Cada bit de la clave "voltea" un bit del carácter, y voltearlo otra vez lo deja como estaba (es una **involución**).

En César, en cambio, la operación es una **suma** modular: `(x + k) mod 26`. Sumar `k` otra vez no regresa al original, lo desplaza `2k`. Para deshacer una suma hay que **restar**, es decir, sumar el inverso aditivo `-k`: `(x + k - k) mod 26 = x`. Por eso en el código `Cesar.descifrar` es simplemente `cifrar(c, -k)`.

### ¿Qué ventajas ofrece el uso de `map` sobre un bucle `for` tradicional en este contexto?

- **Inmutabilidad:** `map` devuelve un `String` nuevo; no se modifica ninguna variable ni se usa un acumulador mutable (`var`, `StringBuilder`).
- **Declarativo:** expresa *qué* se hace ("transformar cada carácter con `funcion`") y no *cómo* recorrer índices; se elimina el riesgo de errores de índice (*off-by-one*).
- **Composición:** encaja naturalmente con funciones de orden superior: la transformación se recibe como parámetro y `map` la aplica, sin cambiar el motor.
- **Concisión y legibilidad:** una línea (`mensaje.map(c => funcion(c, clave))`) reemplaza a un bucle de varias líneas.
- **Sin efectos secundarios:** el resultado depende solo de la entrada, lo que hace la función pura y fácil de probar.

### ¿Cómo ayuda el tipado estático a prevenir errores al pasar funciones como argumentos?

El parámetro `funcion` tiene el tipo `FuncionCifrado = (Char, Int) => Char`. El compilador verifica **antes de ejecutar** que cualquier función pasada reciba exactamente un `Char` y un `Int` y devuelva un `Char`. Por ejemplo, pasar `(c: Char) => c.toUpper` (un solo parámetro) o una lambda que devuelva `Int` (como `(c, k) => c ^ k` sin `.toChar`) produce un **error de compilación**, no un fallo en tiempo de ejecución. Además, el tipo de retorno `Try[String]` obliga a quien llama a considerar el caso de error (`Success` / `Failure`), documentando en la firma que la operación puede fallar.

---

## ✅ Conclusiones

- La función de orden superior `procesarMensaje` permite cambiar la estrategia de cifrado **sin modificar el motor**: basta con pasar otra función `(Char, Int) => Char`.
- `map` aplica la transformación sobre la colección de caracteres de forma inmutable y declarativa.
- `Try` convierte las excepciones en valores (`Success` / `Failure`), lo que permite encadenar operaciones con `flatMap` y recuperarse con `recover` sin que el programa se detenga.
- Se verificaron los casos del enunciado: `FUNCIONAL` → `IXQFLRQDO` → `FUNCIONAL` (César, k = 3) y `scala` → `vfdid` → `scala` (XOR, k = 5).
