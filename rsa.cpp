#include <iostream>
#include <tuple>
#include <cstdint>
#include <stdint.h>
#include <stddef.h>
#include <memory>

#include "../cryptopp/cryptlib.h"
#include "../cryptopp/filters.h"
#include "../cryptopp/files.h"
#include "../cryptopp/modes.h"
#include "../cryptopp/hex.h"
#include "../cryptopp/rsa.h"
#include "../cryptopp/osrng.h"
#include "util.h"

using namespace std;
using namespace CryptoPP;

#define DEBUG 0

class RSAKeyPair{
	public:
		int KeySize;
		int CipherSize;
		RSA::PrivateKey privKey;
		RSA::PublicKey pubKey;

		RSAKeyPair(size_t* Size) {
/*			if(*Size > 86) {
				KeySize = 2048;
				CipherSize = 256;
				if(*Size > 214)
					*Size = 214;
			}
			else {
				KeySize = 1024;
				CipherSize = 128;
			}
*/			
			// Generate Parameters
			AutoSeededRandomPool rng;
			InvertibleRSAFunction params;
			params.GenerateRandomWithKeySize(rng, KeySize);

			// Create Keys
			RSA::PrivateKey privateKey(params);
			RSA::PublicKey publicKey(params);

			privKey = privateKey;
			pubKey = publicKey;
#if DEBUG
cout << "    ===============================================\n";
cout << "[*] DEBUG : RSAEncOAEP()" << endl;
cout << "    KeySize  : " << KeySize << endl;
cout << "    CipherSize : " << CipherSize << endl;
cout << "    Size     : " << *Size << endl;
#endif
		}
};

// Encryption Scheme (OAEP using SHA)
void RSAEncOAEP(RSAKeyPair* RSAKey, uint8_t *Data, size_t Size) {

	AutoSeededRandomPool rng;

	int CipherSize = RSAKey->CipherSize;

	// Obtain Keys
	RSA::PrivateKey privateKey = RSAKey->privKey;
	RSA::PublicKey publicKey = RSAKey->pubKey;

	uint8_t* plain = (uint8_t*)malloc(Size);
	uint8_t* cipher = (uint8_t*)malloc(CipherSize);
	uint8_t* recover = (uint8_t*)malloc(Size);
	memcpy(plain, Data, Size);

	// Encryption
	RSAES_OAEP_SHA_Encryptor e(publicKey);
	ArraySource ss1(plain, Size, true,
		new PK_EncryptorFilter(rng, e,
			new ArraySink(cipher, CipherSize) )
	);

	// Decryption
	RSAES_OAEP_SHA_Decryptor d(privateKey);
	ArraySource ss2(cipher, CipherSize, true,
		new PK_DecryptorFilter(rng, d,
			new ArraySink(recover, Size) )
	);

	// Compare
	compare(plain, recover, Size);

#if DEBUG
	// showParam(params);
	cout << "[*] Plain  : " << endl;
	hexdump(plain, Size);
	cout << "[*] Cipher  : " << endl;
	hexdump(cipher, CipherSize);
	cout << "[*] Recover : " << endl;
	hexdump(recover, Size);
#endif

	free(plain);
	free(cipher);
	free(recover);
}

// Signature Scheme (PKCS v1.5)
void RSASignPKCS(RSAKeyPair* RSAKey, uint8_t *Data, size_t Size) {

	AutoSeededRandomPool rng;

	int CipherSize = RSAKey->CipherSize;

	// Obtain Keys
	RSA::PrivateKey privateKey = RSAKey->privKey;
	RSA::PublicKey publicKey = RSAKey->pubKey;

	// Message
	uint8_t* message = (uint8_t*)malloc(Size);
	uint8_t* signature = (uint8_t*)malloc(CipherSize);
	uint8_t* msg_sig = (uint8_t*)malloc(Size+CipherSize);
	memcpy(message, Data, Size);

	// Sign and Encode
	RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
	ArraySource ss1(message, Size, true,
		new SignerFilter(rng, signer,
			new ArraySink(signature, CipherSize))
	);

	memcpy(msg_sig+0, message, Size);
	memcpy(msg_sig+Size, signature, CipherSize);

	// Verify and Recover
	RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
	ArraySource ss2(msg_sig, Size+CipherSize, true,
		new SignatureVerificationFilter(verifier, NULL,
			SignatureVerificationFilter::THROW_EXCEPTION)
	);

#if DEBUG
	cout << "[*] Message  : " << endl;
	hexdump(message, Size);
	cout << "[*] Sign     : " << endl;
	hexdump(signature, CipherSize);
	cout << "[*] Msg+Sign : " << endl;
	hexdump(msg_sig, Size+CipherSize);
	cout<< endl;
#endif

	free(message);
	free(signature);
	free(msg_sig);
}

void Run(uint8_t *Data, size_t Size) {
	RSAKeyPair RSAKey(&Size);
	RSAEncOAEP(&RSAKey, Data, Size);
	RSASignPKCS(&RSAKey, Data, Size);
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {

	Run(Data, Size);

	return 0;
}

// EOF


