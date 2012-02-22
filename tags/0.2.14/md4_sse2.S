// (C) 2006 Simon Marechal
// 2009 Adapted by Benjamin CHARLES for MacOS X support

.globl md4_sse
.globl _md4_sse

.data
.align(4)

const_init_a:
.long 0x67452301
.long 0x67452301
.long 0x67452301
.long 0x67452301

const_init_b:
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89

const_init_c:
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe

const_init_d:
.long 0x10325476
.long 0x10325476
.long 0x10325476
.long 0x10325476

const_stage2:
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999

const_stage3:
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define tmp1 %xmm4
#define tmp2 %xmm5
#define tmp3 %xmm6
#define tmp4 %xmm7

#define F(x,y,z)        \
	movapd y, tmp1; \
	pxor z, tmp1;   \
	pand x, tmp1;   \
	pxor z, tmp1

#define G(x,y,z)        \
	movapd y, tmp1; \
	movapd y, tmp2; \
	por z, tmp1;    \
	pand z, tmp2;   \
	pand x, tmp1;   \
	por tmp2, tmp1

#define H(x,y,z)        \
	movapd y, tmp1; \
	pxor z, tmp1;   \
	pxor x, tmp1

#define STEP1(f, a, b, c, d, x, s)      \
	f(b, c, d);                     \
	paddd (x*16)(%edx), tmp1;       \
	paddd tmp1, a;                  \
	movapd a, tmp3;                 \
	pslld $s, a;                    \
	psrld $(32-s), tmp3;            \
	por tmp3, a

#define STEP2(f, a, b, c, d, x, s)      \
	f(b, c, d);                     \
	paddd (x*16)(%edx), tmp1;       \
	paddd tmp4, tmp1;               \
	paddd tmp1, a;                  \
	movapd a, tmp3;                 \
	pslld $s, a;                    \
	psrld $(32-s), tmp3;            \
	por tmp3, a

.text

/*
	%eax -> out
	%edx -> in
	%ecx -> n
*/

 md4_sse:
_md4_sse:
	pusha
	shl $3, %ecx
	mov %ecx, 224(%edx)
	mov %ecx, 228(%edx)
	mov %ecx, 232(%edx)
	mov %ecx, 236(%edx)

	movapd const_init_a, ctxa
	movapd const_init_b, ctxb
	movapd const_init_c, ctxc
	movapd const_init_d, ctxd

	STEP1(F, ctxa, ctxb, ctxc, ctxd,  0,  3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc,  1,  7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb,  2, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa,  3, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd,  4,  3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc,  5,  7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb,  6, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa,  7, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd,  8,  3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc,  9,  7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 10, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 11, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 12,  3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 13,  7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 14, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 15, 19)

	movapd const_stage2, tmp4

	STEP2(G, ctxa, ctxb, ctxc, ctxd,  0,  3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc,  4,  5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb,  8,  9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 12, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd,  1,  3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc,  5,  5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb,  9,  9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 13, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd,  2,  3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc,  6,  5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 10,  9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 14, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd,  3,  3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc,  7,  5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 11,  9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 15, 13)

	movapd const_stage3, tmp4

	STEP2(H, ctxa, ctxb, ctxc, ctxd,  0,  3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc,  8,  9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb,  4, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 12, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd,  2,  3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 10,  9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb,  6, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 14, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd,  1,  3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc,  9,  9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb,  5, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 13, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd,  3,  3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 11,  9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb,  7, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 15, 15)

	paddd const_init_a, ctxa
	paddd const_init_b, ctxb
	paddd const_init_c, ctxc
	paddd const_init_d, ctxd

	movapd ctxa,  0(%eax)
	movapd ctxb, 16(%eax)
	movapd ctxc, 32(%eax)
	movapd ctxd, 48(%eax)

	popa
	xor %eax, %eax
	ret

