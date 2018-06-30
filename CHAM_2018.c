/*
 ============================================================================
 Name        : CHAM_2018.c
 Author      : Hwajeong Seo
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 Homepage    : https://crypto.modoo.at
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>

typedef unsigned int 	u32;
typedef unsigned short 	u16;

#define ROR(W,i) (((W)>>(i)) | ((W)<<(16-(i))))
#define ROL(W,i) (((W)<<(i)) | ((W)>>(16-(i))))

#define ROR32(W,i) (((W)>>(i)) | ((W)<<(32-(i))))
#define ROL32(W,i) (((W)<<(i)) | ((W)>>(32-(i))))

/*
CHAM-64/128
secret Key : 0x0100 0x0302 0x0504 0x0706 0x0908 0x0b0a 0x0d0c 0x0f0e
plaintext : 0x1100 0x3322 0x5544 0x7766
ciphertext : 0x453c 0x63bc 0xdcfa 0xbf4e
*/

u16 secretkey64[] = {0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e};
u16 plaintext64[] = {0x1100, 0x3322, 0x5544, 0x7766};
u16 roundkey64[16]= {0,};

void KeyGen64(u16* RK, u16*K){
	u16 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<8;i++){
		tmp0 = ROL(K[i],1);
		tmp1 = ROL(K[i],8);
		tmp2 = ROL(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+8)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc64(u16* X, u16* RK){
	u16 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u16 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i;

	for(i=0;i<40;i++){
		tmp0 = ROL(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		tmp2 = X0^(2*i);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL(tmp3,8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;

		tmp0 = ROL(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		tmp2 = X0^(2*i+1);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL(tmp3,1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}

/*
CHAM-128/128
secret Key : 0x03020100 0x07060504 0x0b0a0908 0x0f0e0d0c
plaintext : 0x33221100 0x77665544 0xbbaa9988 0xffeeddcc
ciphertext : 0xc3746034 0xb55700c5 0x8d64ec32 0x489332f7
*/

u32 secretkey128[] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};
u32 plaintext128[] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
u32 roundkey128[8]= {0,};

void KeyGen128(u32* RK, u32*K){
	u32 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<4;i++){
		tmp0 = ROL32(K[i],1);
		tmp1 = ROL32(K[i],8);
		tmp2 = ROL32(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+4)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc128(u32* X, u32* RK){
	u32 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u32 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i;

	for(i=0;i<40;i++){
		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 8];
		tmp2 = X0^(2*i);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(tmp3,8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 8];
		tmp2 = X0^(2*i+1);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(tmp3,1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}


/*
CHAM-128/256
secret Key : 0x03020100 0x07060504 0x0b0a0908 0x0f0e0d0c 0xf3f2f1f0 0xf7f6f5f4 0xfbfaf9f8 0xfffefdfc
plaintext : 0x33221100 0x77665544 0xbbaa9988 0xffeeddcc
ciphertext : 0xa899c8a0 0xc929d55c 0xab670d38 0x0c4f7ac8
*/

u32 secretkey256[] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc};
u32 plaintext256[] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
u32 roundkey256[16]= {0,};

void KeyGen256(u32* RK, u32*K){
	u32 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<8;i++){
		tmp0 = ROL32(K[i],1);
		tmp1 = ROL32(K[i],8);
		tmp2 = ROL32(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+8)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc256(u32* X, u32* RK){
	u32 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u32 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i;

	for(i=0;i<48;i++){
		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		tmp2 = X0^(2*i);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(tmp3,8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		tmp2 = X0^(2*i+1);
		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(tmp3,1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}

int main(void) {
	//puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */


	KeyGen64(roundkey64,secretkey64);
	Enc64(plaintext64,roundkey64);

	int i;
	for (i=0;i<16;i++){
		//printf("0x%04x,",roundkey64[i]);
		printf("0x%04x,0x%04x,",roundkey64[i],roundkey64[i]);//test
	}
	/**/

	/*
	KeyGen128(roundkey128,secretkey128);
	Enc128(plaintext128,roundkey128);
	int i;
		for (i=0;i<8;i++){
			printf("0x%08x,",roundkey128[i]);
		}
	/**/
/*
	KeyGen256(roundkey256,secretkey256);
	Enc256(plaintext256,roundkey256);

	int i;
			for (i=0;i<16;i++){
				printf("0x%08x,",roundkey256[i]);
			}
			*/
	return EXIT_SUCCESS;
}
