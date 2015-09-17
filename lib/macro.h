#ifndef MACRO_H_
#define MACRO_H_

// 4 * uint8_t => uint32_t
#define U8TO32_LITTLE(p) \
	(((uint32_t)((p)[0])	  ) | ((uint32_t)((p)[1]) << 8) |	\
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// uint32_t => 4 * uint8_t
#define U32TO8_LITTLE(p, x) { 	\
	p[0] = x;		\
	p[1] = x >> 8;		\
	p[2] = x >> 16;		\
	p[3] = x >> 24;		\

// 4 * uint8_t => uint32_t
#define U8TO32_BIG(p) \
	(((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | \
	 ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])))

// 8 * uint8_t => uint64_t
#define U8TO64_BIG(p) \
	(((uint64_t)((p)[0]) << 56) | ((uint64_t)((p)[1]) << 48) | \
	 ((uint64_t)((p)[2]) << 40) | ((uint64_t)((p)[3]) << 32) | \
	 ((uint64_t)((p)[4]) << 24) | ((uint64_t)((p)[5]) << 16) | \
	 ((uint64_t)((p)[6]) << 8)  | ((uint64_t)((p)[7])))

// Selecting byte order 4-bytes
#if __BYTE_ORDER == __BIG_ENDIAN
#define U32TO32(x) \
	((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define U32TO32(x)	(x)
#else
#error unsupported byte order
#endif

// Print 32-bit
#if __BYTE_ORDER == __BIG_ENDIAN
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x >> 24), ((x >> 16) & 0xFF), ((x >> 8) & 0xFF), (x & 0xFF)))
#else
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), (x >> 24)))
#endif

// Cyclic left and right 32 bit shift
#define ROTL32(v, n)	((v << n) | (v >> (32 - n)))
#define ROTR32(v, n)	((v >> n) | (v << (32 - n)))

// Cyclic left and right 64 bit shift
#define ROTL64(v, n)	((v << n) | (v >> (64 - n)))
#define ROTR64(v, n)	((v >> n) | (v << (64 - n)))

// Logic left and right shift
#define SHL(v, n)	((v) << n)
#define SHR(v, n)	((v) >> n)

#endif
