#include <stdio.h>

unsigned char delta[128] = {
		0x5A,0x6D,0x36,0x1B,0x0D,0x06,0x03,0x41,
		0x60,0x30,0x18,0x4C,0x66,0x33,0x59,0x2C,
		0x56,0x2B,0x15,0x4A,0x65,0x72,0x39,0x1C,
		0x4E,0x67,0x73,0x79,0x3C,0x5E,0x6F,0x37,
		0x5B,0x2D,0x16,0x0B,0x05,0x42,0x21,0x50,
		0x28,0x54,0x2A,0x55,0x6A,0x75,0x7A,0x7D,
		0x3E,0x5F,0x2F,0x17,0x4B,0x25,0x52,0x29,
		0x14,0x0A,0x45,0x62,0x31,0x58,0x6C,0x76,
		0x3B,0x1D,0x0E,0x47,0x63,0x71,0x78,0x7C,
		0x7E,0x7F,0x3F,0x1F,0x0F,0x07,0x43,0x61,
		0x70,0x38,0x5C,0x6E,0x77,0x7B,0x3D,0x1E,
		0x4F,0x27,0x53,0x69,0x34,0x1A,0x4D,0x26,
		0x13,0x49,0x24,0x12,0x09,0x04,0x02,0x01,
		0x40,0x20,0x10,0x08,0x44,0x22,0x11,0x48,
		0x64,0x32,0x19,0x0C,0x46,0x23,0x51,0x68,
		0x74,0x3A,0x5D,0x2E,0x57,0x6B,0x35,0x5A };

// 키 스케쥴 수행 함수 선언
void key_schedule(unsigned char* roundKey, unsigned char* masterKey, int masterKeyLen)
{
	int i, j;
	unsigned char WK[8] = { 0, };
	unsigned char SK[136] = { 0, };
	unsigned char SK_decrypt[128] = { 0, };

	for (i = 0; i < 4; i++)
	{
		WK[i] = masterKey[i + 12];
	}
	for (i = 4; i < 8; i++)
	{
		WK[i] = masterKey[i - 4];		//화이트닝키(WK) 생성
	}

	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			SK[16 * i + j] = (masterKey[(j - i) & 7] + delta[16 * i + j]) & 0xFF;
		}
		for (j = 0; j < 8; j++)
		{
			SK[16 * i + j + 8] = (masterKey[((j - i) & 7) + 8] + delta[16 * i + j + 8]) & 0xFF;			//서브키(SK) 생성
		}
	}

	for (i = 0; i < 8; i++)
	{
		roundKey[i] = WK[i];
	}

	for (i = 8; i < 136; i++)
	{
		roundKey[i] = SK[i-8];
	}

	for (i = 0; i < 128; i++)
	{
		SK_decrypt[i] = SK[127 - i];			//복호화용 키 생성
	}
}





// 암호화 수행 함수 선언
int encrypt(unsigned char* ciphertext, unsigned char* plaintext, int ptSize, unsigned char* roundKey)
{
	unsigned char X[33][8];
	unsigned char F0[256] = { 0, };
	unsigned char F1[256] = { 0, };
	int i, j, ciphertext_size;

	for (i = 0; i < 4; i++)
	{
		X[0][(2 * i + 1)] = plaintext[2 * i + 1];
	}

	X[0][0] = (plaintext[0] + roundKey[0]) & 0xFF;
	X[0][2] = (plaintext[2] ^ roundKey[1]);
	X[0][4] = (plaintext[4] + roundKey[2]) & 0xFF;
	X[0][6] = (plaintext[6] ^ roundKey[3]);					//초기변환

	for (i = 0; i < 256; i++)
	{
		F0[i] = ((i << 1) | (i >> (8 - 1))) ^ ((i << 2) | (i >> (8 - 2))) ^ ((i << 7) | (i >> (8 - 7)));
		F1[i] = ((i << 3) | (i >> (8 - 3))) ^ ((i << 4) | (i >> (8 - 4))) ^ ((i << 6) | (i >> (8 - 6)));
	}

	for (i = 1; i < 32; i++)
	{
		X[i][1] = X[i - 1][0];
		X[i][3] = X[i - 1][2];
		X[i][5] = X[i - 1][4];
		X[i][7] = X[i - 1][6];

		X[i][0] = X[i - 1][7] ^ (((F0[X[i - 1][6]]) + roundKey[(4 * i - 1)+8]) & 0xFF);
		X[i][2] = ((X[i - 1][1] + ((F1[X[i - 1][0]]) ^ (roundKey[(4 * i - 4) + 8]))) & 0xFF);
		X[i][4] = X[i - 1][3] ^ (((F0[X[i - 1][2]]) + roundKey[(4 * i - 3) + 8]) & 0xFF);
		X[i][6] = ((X[i - 1][5] + ((F1[X[i - 1][4]]) ^ (roundKey[(4 * i - 2) + 8]))) & 0xFF);
	}

	for (j = 1; j < 5; j++)
	{
		X[32][2 * j - 2] = X[31][2 * j - 2];
	}

	X[32][1] = ((X[31][1] + ((F1[X[31][0]]) ^ (roundKey[132]))) & 0xFF);
	X[32][3] = X[31][3] ^ (((F0[X[31][2]]) + roundKey[133]) & 0xFF);
	X[32][5] = ((X[31][5] + ((F1[X[31][4]]) ^ (roundKey[134]))) & 0xFF);
	X[32][7] = X[31][7] ^ (((F0[X[31][6]]) + roundKey[135]) & 0xFF);


	for (j = 0; j < 4; j++)
	{
		ciphertext[2 * j + 1] = X[32][2 * j + 1];
	}

	ciphertext[0] = ((X[32][0] + roundKey[4]) & 0xFF);
	ciphertext[2] = (X[32][2] ^ (roundKey[5]));
	ciphertext[4] = ((X[32][4] + roundKey[6]) & 0xFF);
	ciphertext[6] = (X[32][6] ^ (roundKey[7]));


	ciphertext_size = sizeof(ciphertext);

	return ciphertext_size;
}


// 복호화 수행 함수 선언
int decrypt(unsigned char* recovered, unsigned char* ciphertext, int ctSize, unsigned char* roundKey)
{
	unsigned char X[33][8];
	unsigned char F0[256] = { 0, };
	unsigned char F1[256] = { 0, };
	int i, j, recovered_size;

	for (i = 0; i < 4; i++)
	{
		X[0][(2 * i + 1)] = ciphertext[2 * i + 1];
	}

	X[0][0] = (ciphertext[0] - roundKey[4]) & 0xFF;
	X[0][2] = (ciphertext[2] ^ roundKey[5]);
	X[0][4] = (ciphertext[4] - roundKey[6]) & 0xFF;
	X[0][6] = (ciphertext[6] ^ roundKey[7]);					//초기변환

	for (i = 0; i < 256; i++)
	{
		F0[i] = ((i << 1) | (i >> (8 - 1))) ^ ((i << 2) | (i >> (8 - 2))) ^ ((i << 7) | (i >> (8 - 7)));
		F1[i] = ((i << 3) | (i >> (8 - 3))) ^ ((i << 4) | (i >> (8 - 4))) ^ ((i << 6) | (i >> (8 - 6)));
	}

	for (i = 1; i < 32; i++)
	{
		X[i][1] = X[i - 1][2];
		X[i][3] = X[i - 1][4];
		X[i][5] = X[i - 1][6];
		X[i][7] = X[i - 1][0];

		
		X[i][0] = ((X[i - 1][1] - ((F1[X[i - 1][0]]) ^ (roundKey[135 - (4 * i - 1)]))) & 0xFF);
		X[i][2] = X[i - 1][3] ^ (((F0[X[i - 1][2]]) + roundKey[135 - (4 * i - 2) ]) & 0xFF);
		X[i][4] = ((X[i - 1][5] - ((F1[X[i - 1][4]]) ^ (roundKey[135 - (4 * i - 3) ]))) & 0xFF);
		X[i][6] = X[i - 1][7] ^ (((F0[X[i - 1][6]]) + roundKey[135 - (4 * i - 4)]) & 0xFF);
	}

	for (j = 1; j < 5; j++)
	{
		X[32][2 * j - 2] = X[31][2 * j - 2];
	}

	X[32][1] = ((X[31][1] - ((F1[X[31][0]]) ^ (roundKey[8]))) & 0xFF);
	X[32][3] = X[31][3] ^ (((F0[X[31][2]]) + roundKey[9]) & 0xFF);
	X[32][5] = ((X[31][5] - ((F1[X[31][4]]) ^ (roundKey[10]))) & 0xFF);
	X[32][7] = X[31][7] ^ (((F0[X[31][6]]) + roundKey[11]) & 0xFF);


	for (j = 0; j < 4; j++)
	{
		recovered[2 * j + 1] = X[32][2 * j + 1];
	}

	recovered[0] = ((X[32][0] - roundKey[0]) & 0xFF);
	recovered[2] = (X[32][2] ^ (roundKey[1]));
	recovered[4] = ((X[32][4] - roundKey[2]) & 0xFF);
	recovered[6] = (X[32][6] ^ (roundKey[3]));


	recovered_size = sizeof(recovered);

	return recovered_size;



}

// 아래 함수에서 암호알고리즘 암복호화 테스트 수행
// Master key (16바이트) : 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
// Test vector 1 (8바이트) : 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
// Test vector 2 (8바이트) : 0xD7, 0x6D, 0x0D,0x18, 0x32, 0x7E, 0xC5, 0x62
// Test vector 3 (8바이트) : 0x7D, 0xD6, 0xD0,0x81, 0x23, 0xE7, 0x5C, 0x26
// Test vector 4 (8바이트) : 0xFF, 0xFF, 0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF
void test_encyption()
{
	int i;
	int ptsize1, ptsize2, ptsize3, ptsize4;
	int masterKeyLen, ciphertext_size, recovered_size;
	unsigned char RoundKey[136] = { 0, };
	unsigned char roundKey[128] = { 0, };
	unsigned char ciphertext[8] = { 0, };
	unsigned char recovered[8] = { 0, };
	unsigned char masterKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char Plaintext1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char Plaintext2[] = { 0xD7, 0x6D, 0x0D,0x18, 0x32, 0x7E, 0xC5, 0x62 };
	unsigned char Plaintext3[] = { 0x7D, 0xD6, 0xD0,0x81, 0x23, 0xE7, 0x5C, 0x26 };
	unsigned char Plaintext4[] = { 0xFF, 0xFF, 0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	ptsize1 = sizeof(Plaintext1);
	ptsize2 = sizeof(Plaintext2);
	ptsize3 = sizeof(Plaintext3);
	ptsize4 = sizeof(Plaintext4);


	masterKeyLen = sizeof(masterKey);
	key_schedule(RoundKey, masterKey, masterKeyLen);

	printf("Master key : ");
	for (i = 0; i < 16; i++)
	{
		printf("%.2X ", masterKey[i]);
	}

	printf("\n");

	printf("\n[1-th Test]\n");
	printf("\nPlaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", Plaintext1[i]);
	}
	printf("\nEncryption....");
	ciphertext_size = encrypt(ciphertext, Plaintext1, ptsize1, RoundKey);
	
	printf("\nCiphertext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", ciphertext[i]);
	}

	printf("\n\nDecryption....\n");
	recovered_size = decrypt(recovered, ciphertext, ciphertext_size, RoundKey);
		
	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", recovered[i]);
	}
	printf("\n");

	////////////////////////////////////////////////////
	printf("\n");
	printf("\n[2-th Test]\n");
	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", Plaintext2[i]);
	}
	printf("\nEncryption....");
	ciphertext_size = encrypt(ciphertext, Plaintext2, ptsize1, RoundKey);

	printf("\nCiphertext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", ciphertext[i]);
	}

	printf("\n\nDecryption....\n");
	recovered_size = decrypt(recovered, ciphertext, ciphertext_size, RoundKey);

	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", recovered[i]);
	}
	printf("\n");
	///////////////////////////////////////////////////////
	printf("\n[3-th Test]\n");
	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", Plaintext3[i]);
	}
	printf("\nEncryption....");
	ciphertext_size = encrypt(ciphertext, Plaintext3, ptsize1, RoundKey);

	printf("\nCiphertext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", ciphertext[i]);
	}

	printf("\n\nDecryption....\n");
	recovered_size = decrypt(recovered, ciphertext, ciphertext_size, RoundKey);

	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", recovered[i]);
	}
	printf("\n");
	//////////////////////////////////////////////////////////////
	printf("\n[4-th Test]\n");
	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", Plaintext4[i]);
	}
	printf("\nEncryption....");
	ciphertext_size = encrypt(ciphertext, Plaintext4, ptsize1, RoundKey);

	printf("\nCiphertext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%.2X ", ciphertext[i]);
	}

	printf("\n\nDecryption....\n");
	recovered_size = decrypt(recovered, ciphertext, ciphertext_size, RoundKey);

	printf("Plaintext : ");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", recovered[i]);
	}
	printf("\n");
}







int main()
{
	test_encyption();
	return 0;
}

