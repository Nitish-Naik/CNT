from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())


alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()


bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

alice_shared_key = alice_private_key.exchange(bob_public_key)

bob_shared_key = bob_private_key.exchange(alice_public_key)

assert alice_shared_key == bob_shared_key

# derive a key

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,
    backend=default_backend()
)


key = kdf.derive(alice_shared_key)


print("Alice public key : ", alice_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

print("Bob's public key : ", bob_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))


print("derived shared key :" , key)


"""
    public class vigenere_cipher_java {
        public static String encrypt(String plaintext, String key){

        plaintext = plaintext.toUpperCase();
        key = key.toUpperCase();
        
        StringBuilder extendedKey = new StringBuilder(key);
        while(extendedKey < plaintext.length()) {
            extended.append(key);
        }

        extendedKey.setLength(plaintext.length());
        key = extendedKey.toString();

        StringBuilder sb = new StringBuilder();

        for(int i=0; i<plaintext.length(); i++) {
            char pChar = plaintext.charAt(i);
            char kChar = plaintext.charAt(i);
            if(Character.isLetter(cPhar)) {
                int pIndex = alphabets.indexOf(pChar);
                int kIndex = alphabets.indexOf(kChar);
                char encryptedChar = alphabets.charAt((pIndex + kIndex) % 26);

                sb.append(encryptedChar);
            }
            else {
            sb.append(encryptedChar);
            }
        }

        return sb.toString();
        }
    }

"""



def encrypt_caesar(plaintext, shift):
    encrypted = []
    for char in plaintext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            encrypted.append(encrypted_char)
        else:
            encrypted.append(char)
    return ''.join(encrypted)

# decrypt
def decrypt_caesar(ciphertext, shift):
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - shift_base - shift) % 26 + shift_base)
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# Example usage
plaintext = input("Enter plaintext: ")
shift = 3  

encrypted_text = encrypt_caesar(plaintext, shift)
print("Encrypted text:", encrypted_text)

decrypted_text = decrypt_caesar(encrypted_text, shift)
print("Decrypted text:", decrypted_text)







# playfair

def toLowerCase(text):
    return text.lower()

# Function to remove all spaces in a string


def removeSpaces(text):
    newText = ""
    for i in text:
        if i == " ":
            continue
        else:
            newText = newText + i
    return newText

# Function to group 2 elements of a string
# as a list element


def Diagraph(text):
    Diagraph = []
    group = 0
    for i in range(2, len(text), 2):
        Diagraph.append(text[group:i])

        group = i
    Diagraph.append(text[group:])
    return Diagraph

# Function to fill a letter in a string element
# If 2 letters in the same string matches


def FillerLetter(text):
    k = len(text)
    if k % 2 == 0:
        for i in range(0, k, 2):
            if text[i] == text[i+1]:
                new_word = text[0:i+1] + str('x') + text[i+1:]
                new_word = FillerLetter(new_word)
                break
            else:
                new_word = text
    else:
        for i in range(0, k-1, 2):
            if text[i] == text[i+1]:
                new_word = text[0:i+1] + str('x') + text[i+1:]
                new_word = FillerLetter(new_word)
                break
            else:
                new_word = text
    return new_word


list1 = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

# Function to generate the 5x5 key square matrix


def generateKeyTable(word, list1):
    key_letters = []
    for i in word:
        if i not in key_letters:
            key_letters.append(i)

    compElements = []
    for i in key_letters:
        if i not in compElements:
            compElements.append(i)
    for i in list1:
        if i not in compElements:
            compElements.append(i)

    matrix = []
    while compElements != []:
        matrix.append(compElements[:5])
        compElements = compElements[5:]

    return matrix


def search(mat, element):
    for i in range(5):
        for j in range(5):
            if(mat[i][j] == element):
                return i, j


def encrypt_RowRule(matr, e1r, e1c, e2r, e2c):
    char1 = ''
    if e1c == 4:
        char1 = matr[e1r][0]
    else:
        char1 = matr[e1r][e1c+1]

    char2 = ''
    if e2c == 4:
        char2 = matr[e2r][0]
    else:
        char2 = matr[e2r][e2c+1]

    return char1, char2


def encrypt_ColumnRule(matr, e1r, e1c, e2r, e2c):
    char1 = ''
    if e1r == 4:
        char1 = matr[0][e1c]
    else:
        char1 = matr[e1r+1][e1c]

    char2 = ''
    if e2r == 4:
        char2 = matr[0][e2c]
    else:
        char2 = matr[e2r+1][e2c]

    return char1, char2


def encrypt_RectangleRule(matr, e1r, e1c, e2r, e2c):
    char1 = ''
    char1 = matr[e1r][e2c]

    char2 = ''
    char2 = matr[e2r][e1c]

    return char1, char2


def encryptByPlayfairCipher(Matrix, plainList):
    CipherText = []
    for i in range(0, len(plainList)):
        c1 = 0
        c2 = 0
        ele1_x, ele1_y = search(Matrix, plainList[i][0])
        ele2_x, ele2_y = search(Matrix, plainList[i][1])

        if ele1_x == ele2_x:
            c1, c2 = encrypt_RowRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
            # Get 2 letter cipherText
        elif ele1_y == ele2_y:
            c1, c2 = encrypt_ColumnRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
        else:
            c1, c2 = encrypt_RectangleRule(
                Matrix, ele1_x, ele1_y, ele2_x, ele2_y)

        cipher = c1 + c2
        CipherText.append(cipher)
    return CipherText


text_Plain = 'instruments'
text_Plain = removeSpaces(toLowerCase(text_Plain))
PlainTextList = Diagraph(FillerLetter(text_Plain))
if len(PlainTextList[-1]) != 2:
    PlainTextList[-1] = PlainTextList[-1]+'z'

key = "Monarchy"
print("Key text:", key)
key = toLowerCase(key)
Matrix = generateKeyTable(key, list1)

print("Plain Text:", text_Plain)
CipherList = encryptByPlayfairCipher(Matrix, PlainTextList)

CipherText = ""
for i in CipherList:
    CipherText += i
print("CipherText:", CipherText)














# rail fence
// Java program to illustrate Rail Fence Cipher
// Encryption and Decryption
import java.util.Arrays;
class RailFence {

	// function to encrypt a message
	public static String encryptRailFence(String text,
										int key)
	{

		// create the matrix to cipher plain text
		// key = rows , length(text) = columns
		char[][] rail = new char[key][text.length()];

		// filling the rail matrix to distinguish filled
		// spaces from blank ones
		for (int i = 0; i < key; i++)
			Arrays.fill(rail[i], '\n');

		boolean dirDown = false;
		int row = 0, col = 0;

		for (int i = 0; i < text.length(); i++) {

			// check the direction of flow
			// reverse the direction if we've just
			// filled the top or bottom rail
			if (row == 0 || row == key - 1)
				dirDown = !dirDown;

			// fill the corresponding alphabet
			rail[row][col++] = text.charAt(i);

			// find the next row using direction flag
			if (dirDown)
				row++;
			else
				row--;
		}

		// now we can construct the cipher using the rail
		// matrix
		StringBuilder result = new StringBuilder();
		for (int i = 0; i < key; i++)
			for (int j = 0; j < text.length(); j++)
				if (rail[i][j] != '\n')
					result.append(rail[i][j]);

		return result.toString();
	}

	// This function receives cipher-text and key
	// and returns the original text after decryption
	public static String decryptRailFence(String cipher,
										int key)
	{

		// create the matrix to cipher plain text
		// key = rows , length(text) = columns
		char[][] rail = new char[key][cipher.length()];

		// filling the rail matrix to distinguish filled
		// spaces from blank ones
		for (int i = 0; i < key; i++)
			Arrays.fill(rail[i], '\n');

		// to find the direction
		boolean dirDown = true;

		int row = 0, col = 0;

		// mark the places with '*'
		for (int i = 0; i < cipher.length(); i++) {
			// check the direction of flow
			if (row == 0)
				dirDown = true;
			if (row == key - 1)
				dirDown = false;

			// place the marker
			rail[row][col++] = '*';

			// find the next row using direction flag
			if (dirDown)
				row++;
			else
				row--;
		}

		// now we can construct the fill the rail matrix
		int index = 0;
		for (int i = 0; i < key; i++)
			for (int j = 0; j < cipher.length(); j++)
				if (rail[i][j] == '*'
					&& index < cipher.length())
					rail[i][j] = cipher.charAt(index++);

		StringBuilder result = new StringBuilder();

		row = 0;
		col = 0;
		for (int i = 0; i < cipher.length(); i++) {
			// check the direction of flow
			if (row == 0)
				dirDown = true;
			if (row == key - 1)
				dirDown = false;

			// place the marker
			if (rail[row][col] != '*')
				result.append(rail[row][col++]);

			// find the next row using direction flag
			if (dirDown)
				row++;
			else
				row--;
		}
		return result.toString();
	}


	public static void main(String[] args)
	{

		// Encryption
		System.out.println("Encrypted Message: ");
		System.out.println(
			encryptRailFence("attack at once", 2));
		System.out.println(
			encryptRailFence("GeeksforGeeks ", 3));
		System.out.println(
			encryptRailFence("defend the east wall", 3));

		// Now decryption of the same cipher-text
		System.out.println("\nDecrypted Message: ");
		System.out.println(
			decryptRailFence("atc toctaka ne", 2));
		System.out.println(
			decryptRailFence("GsGsekfrek eoe", 3));
		System.out.println(
			decryptRailFence("dnhaweedtees alf tl", 3));
	}
}






















# des
# Python3 code for the above approach

# Hexadecimal to binary conversion


def hex2bin(s):
	mp = {'0': "0000",
		'1': "0001",
		'2': "0010",
		'3': "0011",
		'4': "0100",
		'5': "0101",
		'6': "0110",
		'7': "0111",
		'8': "1000",
		'9': "1001",
		'A': "1010",
		'B': "1011",
		'C': "1100",
		'D': "1101",
		'E': "1110",
		'F': "1111"}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin

# Binary to hexadecimal conversion


def bin2hex(s):
	mp = {"0000": '0',
		"0001": '1',
		"0010": '2',
		"0011": '3',
		"0100": '4',
		"0101": '5',
		"0110": '6',
		"0111": '7',
		"1000": '8',
		"1001": '9',
		"1010": 'A',
		"1011": 'B',
		"1100": 'C',
		"1101": 'D',
		"1110": 'E',
		"1111": 'F'}
	hex = ""
	for i in range(0, len(s), 4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]

	return hex

# Binary to decimal conversion


def bin2dec(binary):

	binary1 = binary
	decimal, i, n = 0, 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal

# Decimal to binary conversion


def dec2bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res

# Permute function to rearrange the bits


def permute(k, arr, n):
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation

# shifting the bits towards left by nth shifts


def shift_left(k, nth_shifts):
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k

# calculating xow of two strings of binary number a and b


def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans


# Table of Position of 64 bits at initial level: Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]


def encrypt(pt, rkb, rk):
	pt = hex2bin(pt)

	# Initial Permutation
	pt = permute(pt, initial_perm, 64)
	print("After initial permutation", bin2hex(pt))

	# Splitting
	left = pt[0:32]
	right = pt[32:64]
	for i in range(0, 16):
		# Expansion D-box: Expanding the 32 bits data into 48 bits
		right_expanded = permute(right, exp_d, 48)

		# XOR RoundKey[i] and right_expanded
		xor_x = xor(right_expanded, rkb[i])

		# S-boxex: substituting the value from s-box table by calculating row and column
		sbox_str = ""
		for j in range(0, 8):
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
			col = bin2dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec2bin(val)

		# Straight D-box: After substituting rearranging the bits
		sbox_str = permute(sbox_str, per, 32)

		# XOR left and sbox_str
		result = xor(left, sbox_str)
		left = result

		# Swapper
		if(i != 15):
			left, right = right, left
		print("Round ", i + 1, " ", bin2hex(left),
			" ", bin2hex(right), " ", rk[i])

	# Combination
	combine = left + right

	# Final permutation: final rearranging of bits to get cipher text
	cipher_text = permute(combine, final_perm, 64)
	return cipher_text


pt = "123456ABCD132536"
key = "AABB09182736CCDD"

# Key generation
# --hex to binary
key = hex2bin(key)

# --parity bit drop table
keyp = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]

# getting 56 bit key from 64 bit using the parity bits
key = permute(key, keyp, 56)

# Number of bit shifts
shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]

# Key- Compression Table : Compression of key from 56 bits to 48 bits
key_comp = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]

# Splitting
left = key[0:28] # rkb for RoundKeys in binary
right = key[28:56] # rk for RoundKeys in hexadecimal

rkb = []
rk = []
for i in range(0, 16):
	# Shifting the bits by nth shifts by checking from shift table
	left = shift_left(left, shift_table[i])
	right = shift_left(right, shift_table[i])

	# Combination of left and right string
	combine_str = left + right

	# Compression of key from 56 to 48 bits
	round_key = permute(combine_str, key_comp, 48)

	rkb.append(round_key)
	rk.append(bin2hex(round_key))

print("Encryption")
cipher_text = bin2hex(encrypt(pt, rkb, rk))
print("Cipher Text : ", cipher_text)

print("Decryption")
rkb_rev = rkb[::-1]
rk_rev = rk[::-1]
text = bin2hex(encrypt(cipher_text, rkb_rev, rk_rev))
print("Plain Text : ", text)

# ouput
...60AF7CA5
Round 12 FF3C485F 22A5963B C2C1E96A4BF3
Round 13 22A5963B 387CCDAA 99C31397C91F
Round 14 387CCDAA BD2DD2AB 251B8BC717D0
Round 15 BD2DD2AB CF26B472 3330C5D9A36D
Round 16 19BA9212 CF26B472 181C5D75C66D

Cipher Text: C0B7A8D05F3A829C

Decryption

After initial permutation: 19BA9212CF26B472
After splitting: L0=19BA9212 R0=CF26B472

Round 1 CF26B472 BD2DD2AB 181C5D75C66D
Round 2 BD2DD2AB 387CCDAA 3330C5D9A36D
Round 3 387CCDAA 22A5963B 251B8BC717D0
Round 4 22A5963B FF3C485F 99C31397C91F
Round 5 FF3C485F 6CA6CB20 C2C1E96A4BF3
Round 6 6CA6CB20 10AF9D37 6D5560AF7CA5
Round 7 10AF9D37 308BEE97 02765708B5BF
Round 8 308BEE97 A9FC20A3 84BB4473DCCC
Round 9 A9FC20A3 2E8F9C65 34F822F0C66D
Round 10 2E8F9C65 A15A4B87 708AD2DDB3C0
Round 11 A15A4B87 236779C2 C1948E87475E
Round 12 236779C2 B8089591 69A629FEC913
Round 13 B8089591 4A1210F6 DA2D032B6EE3
Round 14 4A1210F6 5A78E394 06EDA4ACF5B5
Round 15 5A78E394 18CA18AD 4568581ABCCE
Round 16 14A7D678 18CA18AD 194CD072DE8C

Plain Text: 123456ABCD132536
















# aes
Here is a simple implementation of the **Advanced Encryption Standard (AES)** algorithm for symmetric key encryption using Python's `PyCryptodome` library. This example demonstrates how to encrypt and decrypt text using AES.

First, make sure you have the `PyCryptodome` library installed. You can install it via pip:

```bash
pip install pycryptodome
```

Now, here is the basic code:

### AES Encryption and Decryption in Python:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Pad the data to make it a multiple of AES block size (16 bytes)
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

# Unpad the decrypted text
def unpad(text):
    return text[:-ord(text[len(text) - 1:])]

# Function to encrypt plaintext
def encrypt_AES(key, data):
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Pad the data
    padded_data = pad(data)
    
    # Encrypt data
    encrypted_bytes = cipher.encrypt(padded_data.encode('utf-8'))
    
    # Return base64 encoded string of the encrypted data
    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Function to decrypt ciphertext
def decrypt_AES(key, enc_data):
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decode the base64 encoded ciphertext
    enc_data_bytes = base64.b64decode(enc_data)
    
    # Decrypt the data
    decrypted_padded_data = cipher.decrypt(enc_data_bytes).decode('utf-8')
    
    # Unpad the decrypted data
    return unpad(decrypted_padded_data)

# Main part
if __name__ == "__main__":
    # Symmetric key (must be either 16, 24, or 32 bytes long)
    key = get_random_bytes(16)  # 16 bytes = 128-bit key
    
    # Original plaintext
    plaintext = "This is a secret message."
    
    # Encrypt the plaintext
    encrypted = encrypt_AES(key, plaintext)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt the ciphertext
    decrypted = decrypt_AES(key, encrypted)
    print(f"Decrypted: {decrypted}")
```

### Explanation:

1. **Padding**: AES requires the input text to be a multiple of the block size (16 bytes). The `pad()` function adds padding to the plaintext to ensure it meets this requirement, while `unpad()` removes the padding after decryption.
2. **ECB Mode**: We use ECB (Electronic Codebook) mode for simplicity. ECB mode encrypts each block of data independently but isn't the most secure mode. Other modes (e.g., CBC) are more secure for real-world applications.
3. **Key Generation**: The key must be of size 16, 24, or 32 bytes, corresponding to AES-128, AES-192, and AES-256, respectively. Here, we randomly generate a 16-byte key (AES-128).

### Output Example:
```
Encrypted: GJqkls1yKiG1c4TSH7R2sRNBACJS9khjgzZr1MqVc3E=
Decrypted: This is a secret message.
```



# rsa in python
                                                      # Python for RSA asymmetric cryptographic algorithm.
# For demonstration, values are
# relatively small compared to practical application
import math


def gcd(a, h):
    temp = 0
    while(1):
        temp = a % h
        if (temp == 0):
            return h
        a = h
        h = temp


p = 3
q = 7
n = p*q
e = 2
phi = (p-1)*(q-1)

while (e < phi):

    # e must be co-prime to phi and
    # smaller than phi.
    if(gcd(e, phi) == 1):
        break
    else:
        e = e+1

# Private key (d stands for decrypt)
# choosing d such that it satisfies
# d*e = 1 + k * totient

k = 2
d = (1 + (k*phi))/e

# Message to be encrypted
msg = 12.0

print("Message data = ", msg)

# Encryption c = (msg ^ e) % n
c = pow(msg, e)
c = math.fmod(c, n)
print("Encrypted data = ", c)

# Decryption m = (c ^ d) % n
m = pow(c, d)
m = math.fmod(m, n)
print("Original Message Sent = ", m)


# This code is contributed by Pranay Arora.



# rsa in java
/*package whatever //do not write package name here */
import java.io.*;
import java.math.*;
import java.util.*;
/*
 * Java program for RSA asymmetric cryptographic algorithm.
 * For demonstration, values are
 * relatively small compared to practical application
 */
public class GFG {
    public static double gcd(double a, double h)
    {
        /*
         * This function returns the gcd or greatest common
         * divisor
         */
        double temp;
        while (true) {
            temp = a % h;
            if (temp == 0)
                return h;
            a = h;
            h = temp;
        }
    }
    public static void main(String[] args)
    {
        double p = 3;
        double q = 7;

        // Stores the first part of public key:
        double n = p * q;

        // Finding the other part of public key.
        // double e stands for encrypt
        double e = 2;
        double phi = (p - 1) * (q - 1);
        while (e < phi) {
            /*
             * e must be co-prime to phi and
             * smaller than phi.
             */
            if (gcd(e, phi) == 1)
                break;
            else
                e++;
        }
        int k = 2; // A constant value
        double d = (1 + (k * phi)) / e;

        // Message to be encrypted
        double msg = 12;

        System.out.println("Message data = " + msg);

        // Encryption c = (msg ^ e) % n
        double c = Math.pow(msg, e);
        c = c % n;
        System.out.println("Encrypted data = " + c);

        // Decryption m = (c ^ d) % n
        double m = Math.pow(c, d);
        m = m % n;
        System.out.println("Original Message Sent = " + m);
    }
}


