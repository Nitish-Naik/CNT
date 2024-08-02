public class Vigenere_cipher_java {

    public static String encrypt(String plaintext, String key) {
        String alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Ensure plaintext and key are uppercase
        plaintext = plaintext.toUpperCase();
        key = key.toUpperCase();

        // Extend the key
        StringBuilder extendedKey = new StringBuilder(key);
        while (extendedKey.length() < plaintext.length()) {
            extendedKey.append(key);
        }
        extendedKey.setLength(plaintext.length());
        key = extendedKey.toString();

        // Encrypt the plaintext
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            char pChar = plaintext.charAt(i);
            char kChar = key.charAt(i);
            if (Character.isLetter(pChar)) {
                int pIndex = alphabets.indexOf(pChar);
                int kIndex = alphabets.indexOf(kChar);
                char encryptedChar = alphabets.charAt((pIndex + kIndex) % 26);
                sb.append(encryptedChar);
            } else {
                sb.append(pChar);
            }
        }
        return sb.toString();
    }

    public static String decrypt(String encryptedText, String key) {
        String alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Ensure encryptedText and key are uppercase
        encryptedText = encryptedText.toUpperCase();
        key = key.toUpperCase();

        // Extend the key
        StringBuilder extendedKey = new StringBuilder(key);
        while (extendedKey.length() < encryptedText.length()) {
            extendedKey.append(key);
        }
        extendedKey.setLength(encryptedText.length());
        key = extendedKey.toString();

        // Decrypt the encrypted text
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encryptedText.length(); i++) {
            char eChar = encryptedText.charAt(i);
            char kChar = key.charAt(i);
            if (Character.isLetter(eChar)) {
                int eIndex = alphabets.indexOf(eChar);
                int kIndex = alphabets.indexOf(kChar);
                // Adjust for negative result
                int decryptedIndex = (eIndex - kIndex + 26) % 26;
                char decryptedChar = alphabets.charAt(decryptedIndex);
                sb.append(decryptedChar);
            } else {
                sb.append(eChar);
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String plaintext = "GEEKSFORGEEKS";
        String key = "ayush";

        String encryptedText = encrypt(plaintext, key);
        String decryptedText = decrypt(encryptedText, key);

        System.out.println("Encrypted text = " + encryptedText);
        System.out.println("Decrypted text = " + decryptedText);
    }
}
