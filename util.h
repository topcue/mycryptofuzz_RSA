#include <ctype.h>
#include <stdio.h>

using namespace std;
using namespace CryptoPP;

#define COMPARE(a, b, x) x += (a - b)

void compare(uint8_t* a, uint8_t* b, size_t Size) {
	int x = 0;
	for (int i = 0; i < Size; i++)
		COMPARE(a[i], b[i], x);
	if (x) {
		cout << "[-] DIFF" << endl;
		exit(0);
	}
}

void hexdump(void *ptr, int buflen) {
	if(!buflen)
		return;
	unsigned char *buf = (unsigned char*)ptr;
	printf("    ");
	for (int i = 1; i < buflen+1; i++) {
		printf("%02x ", buf[i-1]);
		if(!(i & 0xf))
			printf("\n    ");
	}
	if(buflen & 0xf)
		printf("\n");
	printf("\n");
}

void showParam(InvertibleRSAFunction params) {
	// Generated Parameters
	const Integer& n = params.GetModulus();
	const Integer& p = params.GetPrime1();
	const Integer& q = params.GetPrime2();
	const Integer& d = params.GetPrivateExponent();
	const Integer& e = params.GetPublicExponent();

	// Dump
	cout << "[*] RSA Parameters :" << endl;
	cout << "    n: " << n << endl;
	cout << "    p: " << p << endl;
	cout << "    q: " << q << endl;
	cout << "    d: " << d << endl;
	cout << "    e: " << e << endl;
}

// EOF

