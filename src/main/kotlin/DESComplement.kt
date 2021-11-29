import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.xml.bind.DatatypeConverter.parseHexBinary
import javax.xml.bind.DatatypeConverter.printHexBinary
import kotlin.experimental.xor

class DESComplement(keyHex: String, plaintextHex: String) {

    /*
     * DES has a 64-bit plaintext which is split into two 32-bit halves L and R.
     * This splitting is done by rearranging the bits in a semi-ordered fashion (this serves no cryptographic effect).
     * A similar swapping happens at the end of encryption to create the 64-bit ciphertext from the two halves L and R.
     * DES is of Feistel construction.
     *
     * L                          Ki              R
     * |                          |               |
     * ⊕ <- f(Bit shuffle <- S <- ⊕ <- Expand) <- |
     * |                                          |
     * Swap L and R and repeat round
     */


    /**
     * Set initialization vector to a byte array of all zeros.
     */
    private val iv = IvParameterSpec(ByteArray(8))

    /*
     *   _  _    _______
     * E(K, P) = E(K, P)
     *
     *                                   _
     * For all keys and plaintexts where X is the value obtained by complementing all the bits in X.
     * If you encrypt the complement of the plaintext with the complement of the key you get the complement of the original cipher.
     */
    init {
        // E(K, P)
        val cipherHex = encrypt(keyHex, plaintextHex)

        val cKeyHex = complement(keyHex)
        val cTextHex = complement(plaintextHex)

        //   _  _
        // E(K, P)
        val cCipherHex = encrypt(cKeyHex, cTextHex)

        // _______
        // E(K, P)
        val cOriginalCipher = complement(cipherHex)
        println("Complement Cipher: $cCipherHex, Cipher: $cOriginalCipher}")
    }

    /**
     * Encrypts given text with a given key in DES, cipher block chaining, no padding.
     *
     * @param  keyHex  the hex key string to use as a key
     * @param  textHex the hex text to encrypt
     * @return String
     */
    private fun encrypt(keyHex: String, textHex: String): String {
        // Convert key and text to byte arrays.
        val keyBytes = parseHexBinary(keyHex)
        val textBytes = parseHexBinary(textHex)

        // Create secret key for Data Encryption Standard.
        val key  = SecretKeyFactory.getInstance("DES").generateSecret(DESKeySpec(keyBytes))

        // Get cipher for DES using mode cipher block chaining without padding.
        val cipher = Cipher.getInstance("DES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)

        // Run cipher with text bytes.
        val cipherBytes = cipher.doFinal(textBytes)

        // Return bytes as a string of hex.
        return printHexBinary(cipherBytes)
    }

    /**
     * For a given hex string finds the complement performing an XOR operation on each byte with -1, similar to Twos Complement.
     *
     * @param  hex the string to find a complement for
     * @return String
     */
    private fun complement(hex: String): String {
        // Convert hex to byte array.
        val bytes = parseHexBinary(hex)
        // Initialize a byte array of equal size to bytes array.
        val result = ByteArray(bytes.size)

        // For each byte perform an XOR operation with the byte of -1.
        bytes.forEachIndexed { index, byte ->
            result[index] = byte xor 0xFF.toByte()
        }

        // Return result as a string of hex.
        return printHexBinary(result)
    }
}