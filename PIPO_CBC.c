
#include <stdio.h>     // fopen, fseek, ftell, fread, fclose 함수가 선언된 헤더 파일
#include <stdlib.h>

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
		roundKey[i] = SK[i - 8];
	}

	for (i = 0; i < 128; i++)
	{
		SK_decrypt[i] = SK[127 - i];			//복호화용 키 생성
	}
}

// 암호화 수행 함수 선언
int encrypt(unsigned char* ciphertext, unsigned char* plaintext, int ptSize, unsigned char* IV, unsigned char* roundKey)
{
	unsigned char X[33][8];
	unsigned char F0[256] = { 0, };
	unsigned char F1[256] = { 0, };
	int i, j, k;
	int ciphertext_size ;
	unsigned char pt_return[8] = { 0, };



	if (ptSize % 8 == 0)
	{
		ptSize = ptSize;
	}
	else
	{
		//패딩을 해야한다.
		for (i = ptSize + 1; i < ptSize + 9 - (ptSize % 8); i++)
		{
			plaintext[i] = 0;
			ptSize = sizeof(plaintext);
		}
	}

	
	//평문을 8비트씩 나누기
	for (i = 0; i < ptSize / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			plaintext[j + i * 8] = plaintext[j + i * 8];
		}
	}

	//iv plaintext[0]~[7]까지 iv로 xor하기
	for (i = 0; i < 8; i++)
	{
		plaintext[i] = IV[i] ^ plaintext[i];
	}


	for (k = 0; k < ptSize / 8; k++)
	{	
		if (k != 0)
		{
			for (i = 0; i < 8; i++)
			{
				plaintext[k * 8 + i] =  pt_return[i] ^ plaintext[k * 8 + i];
			}
		}
		

		for (i = 0; i < 4; i++)
		{
			X[0][(2 * i + 1)] = plaintext[8 * k + 2 * i + 1];
		}

		X[0][0] = (plaintext[8 * k + 0] + roundKey[0]) & 0xFF;
		X[0][2] = (plaintext[8 * k + 2] ^ roundKey[1]);
		X[0][4] = (plaintext[8 * k + 4] + roundKey[2]) & 0xFF;
		X[0][6] = (plaintext[8 * k + 6] ^ roundKey[3]);					//초기변환

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

			X[i][0] = X[i - 1][7] ^ (((F0[X[i - 1][6]]) + roundKey[(4 * i - 1) + 8]) & 0xFF);
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
			ciphertext[8 * k + 2 * j + 1] = X[32][2 * j + 1];
		}

		ciphertext[8 * k + 0] = ((X[32][0] + roundKey[4]) & 0xFF);
		ciphertext[8 * k + 2] = (X[32][2] ^ (roundKey[5]));
		ciphertext[8 * k + 4] = ((X[32][4] + roundKey[6]) & 0xFF);
		ciphertext[8 * k + 6] = (X[32][6] ^ (roundKey[7]));


		for (i = 0; i < 8; i++)
		{
			pt_return[i] = ciphertext[8 * k + i];
		 	
		}
	}

	ciphertext_size = sizeof(ciphertext);
	
	
	return ciphertext_size;
	
}



// 복호화 수행 함수 선언
int decrypt(unsigned char* recovered, unsigned char* ciphertext, int ctSize, unsigned char* IV, unsigned char* roundKey)
{
	unsigned char X[33][8];
	unsigned char F0[256] = { 0, };
	unsigned char F1[256] = { 0, };
	int i, j, k, recovered_size;
	unsigned char ct_return[8] = { 0, };

	//평문을 8비트씩 나누기
	for (i = 0; i < ctSize / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			ciphertext[j + i * 8] = ciphertext[j + i * 8];
		}
	}


	for (k = 0; k < ctSize / 8; k++)
	{
		for (i = 0; i < 4; i++)
		{
			X[0][(2 * i + 1)] = ciphertext[8 * k + 2 * i + 1];
		}

		X[0][0] = (ciphertext[8 * k + 0] - roundKey[4]) & 0xFF;
		X[0][2] = (ciphertext[8 * k + 2] ^ roundKey[5]);
		X[0][4] = (ciphertext[8 * k + 4] - roundKey[6]) & 0xFF;
		X[0][6] = (ciphertext[8 * k + 6] ^ roundKey[7]);					//초기변환

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
			X[i][2] = X[i - 1][3] ^ (((F0[X[i - 1][2]]) + roundKey[135 - (4 * i - 2)]) & 0xFF);
			X[i][4] = ((X[i - 1][5] - ((F1[X[i - 1][4]]) ^ (roundKey[135 - (4 * i - 3)]))) & 0xFF);
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
			recovered[8 * k + 2 * j + 1] = X[32][2 * j + 1];
		}

		recovered[8 * k + 0] = ((X[32][0] - roundKey[0]) & 0xFF);
		recovered[8 * k + 2] = (X[32][2] ^ (roundKey[1]));
		recovered[8 * k + 4] = ((X[32][4] - roundKey[2]) & 0xFF);
		recovered[8 * k + 6] = (X[32][6] ^ (roundKey[3]));


		//iv plaintext[0]~[8]까지 iv로 xor하기
		if (k == 0)
		{
			for (i = 0; i < 8; i++)
			{
				recovered[8 * k + i] = IV[i] ^ recovered[8 * k + i];
			}
		}
		else
		{
			for (i = 0; i < 8; i++)
			{
				recovered[8 * k + i] = ciphertext[8 * (k - 1) + i] ^ recovered[8 * k + i];

			}

		}
		

	}
	

	recovered_size = sizeof(recovered);

	return recovered_size;
}


void HW1_cbc_test()
{
	unsigned char iv[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };  //iv값
	unsigned char data[128] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,
								0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00,
								0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11,
								0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,0x00, 0x11, 0x22,
								0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11, 0x22, 0x33,
								0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,0x00, 0x11, 0x22, 0x33, 0x44,
								0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
								0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, };
	// 마스터 키
	unsigned char pbUserKey[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };


	int i;


	unsigned char Plaintext[128] = { 0, };
	unsigned char ciphertext[128] = { 0, };
	unsigned char recoverdtext[] = { 0, };
	int ptsize;
	int masterKeyLen, ciphertext_size, recovered_size;
	unsigned char RoundKey[136] = { 0, };
	unsigned char roundKey[128] = { 0, };
	unsigned char recovered[128] = { 0, };


	ptsize = sizeof(data);
	masterKeyLen = sizeof(pbUserKey);
	key_schedule(RoundKey, pbUserKey, masterKeyLen);



	printf("\n[plaintext]\n");
	for (i = 0; i < 128; i++)
	{
		printf("%.2X ", data[i]);
		if (i % 8 == 7)
		{
			printf("\n");
		}
	}

	ciphertext_size = encrypt(ciphertext, data, ptsize, iv, RoundKey);
	

	printf("\n[Ciphertext]\n");
	for (i = 0; i < ptsize; i++)
	{
		printf("%.2X ", ciphertext[i]);
		if (i % 8 == 7)
		{
			printf("\n");
		}
	}

	recovered_size = decrypt(recovered, ciphertext, ptsize, iv, RoundKey);


	printf("\n[recoveredtext]\n");
	for (i = 0; i < ptsize; i++)
	{
		printf("%.2X ", recovered[i]);
		if (i % 8 == 7)
		{
			printf("\n");
		}
	}

}

int main()
{
	HW1_cbc_test();
	//HW2_cbc_test_with_file();
	return 0;

}