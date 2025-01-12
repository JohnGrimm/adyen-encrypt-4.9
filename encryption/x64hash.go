package encryptions

import "fmt"

func x64Add(m, n [2]uint32) [2]uint32 {
	m0 := m[0] >> 16
	m1 := m[0] & 0xffff
	m2 := m[1] >> 16
	m3 := m[1] & 0xffff
	n0 := n[0] >> 16
	n1 := n[0] & 0xffff
	n2 := n[1] >> 16
	n3 := n[1] & 0xffff
	o := [4]uint32{0, 0, 0, 0}
	o[3] += m3 + n3
	o[2] += o[3] >> 16
	o[3] &= 0xffff
	o[2] += m2 + n2
	o[1] += o[2] >> 16
	o[2] &= 0xffff
	o[1] += m1 + n1
	o[0] += o[1] >> 16
	o[1] &= 0xffff
	o[0] += m0 + n0
	o[0] &= 0xffff
	return [2]uint32{(o[0] << 16) | o[1], (o[2] << 16) | o[3]}
}

func x64Multiply(m, n [2]uint32) [2]uint32 {
	m0 := m[0] >> 16
	m1 := m[0] & 0xffff
	m2 := m[1] >> 16
	m3 := m[1] & 0xffff
	n0 := n[0] >> 16
	n1 := n[0] & 0xffff
	n2 := n[1] >> 16
	n3 := n[1] & 0xffff
	o := [4]uint32{0, 0, 0, 0}
	o[3] += m3 * n3
	o[2] += o[3] >> 16
	o[3] &= 0xffff
	o[2] += m2 * n3
	o[1] += o[2] >> 16
	o[2] &= 0xffff
	o[2] += m3 * n2
	o[1] += o[2] >> 16
	o[2] &= 0xffff
	o[1] += m1 * n3
	o[0] += o[1] >> 16
	o[1] &= 0xffff
	o[1] += m2 * n2
	o[0] += o[1] >> 16
	o[1] &= 0xffff
	o[1] += m3 * n1
	o[0] += o[1] >> 16
	o[1] &= 0xffff
	o[0] += (m0 * n3) + (m1 * n2) + (m2 * n1) + (m3 * n0)
	o[0] &= 0xffff
	return [2]uint32{(o[0] << 16) | o[1], (o[2] << 16) | o[3]}
}

func x64Rotl(m [2]uint32, n int) [2]uint32 {
	n %= 64
	if n == 32 {
		return [2]uint32{m[1], m[0]}
	} else if n < 32 {
		return [2]uint32{(m[0] << n) | (m[1] >> (32 - n)), (m[1] << n) | (m[0] >> (32 - n))}
	} else {
		n -= 32
		return [2]uint32{(m[1] << n) | (m[0] >> (32 - n)), (m[0] << n) | (m[1] >> (32 - n))}
	}
}

func x64LeftShift(m [2]uint32, n int) [2]uint32 {
	n %= 64
	if n == 0 {
		return m
	} else if n < 32 {
		return [2]uint32{(m[0] << n) | (m[1] >> (32 - n)), m[1] << n}
	} else {
		return [2]uint32{m[1] << (n - 32), 0}
	}
}

func x64Xor(m, n [2]uint32) [2]uint32 {
	return [2]uint32{m[0] ^ n[0], m[1] ^ n[1]}
}

func x64Fmix(h [2]uint32) [2]uint32 {
	h = x64Xor(h, [2]uint32{0, h[0] >> 1})
	h = x64Multiply(h, [2]uint32{0xff51afd7, 0xed558ccd})
	h = x64Xor(h, [2]uint32{0, h[0] >> 1})
	h = x64Multiply(h, [2]uint32{0xc4ceb9fe, 0x1a85ec53})
	h = x64Xor(h, [2]uint32{0, h[0] >> 1})
	return h
}

func X64hash128(key string, seed uint32) string {
	remainder := len(key) % 16
	bytes := len(key) - remainder
	h1 := [2]uint32{0, seed}
	h2 := [2]uint32{0, seed}
	k1 := [2]uint32{0, 0}
	k2 := [2]uint32{0, 0}
	c1 := [2]uint32{0x87c37b91, 0x114253d5}
	c2 := [2]uint32{0x4cf5ad43, 0x2745937f}
	for i := 0; i < bytes; i += 16 {
		k1 = [2]uint32{
			uint32(key[i+4]) | uint32(key[i+5])<<8 | uint32(key[i+6])<<16 | uint32(key[i+7])<<24,
			uint32(key[i]) | uint32(key[i+1])<<8 | uint32(key[i+2])<<16 | uint32(key[i+3])<<24,
		}
		k2 = [2]uint32{
			uint32(key[i+12]) | uint32(key[i+13])<<8 | uint32(key[i+14])<<16 | uint32(key[i+15])<<24,
			uint32(key[i+8]) | uint32(key[i+9])<<8 | uint32(key[i+10])<<16 | uint32(key[i+11])<<24,
		}
		k1 = x64Multiply(k1, c1)
		k1 = x64Rotl(k1, 31)
		k1 = x64Multiply(k1, c2)
		h1 = x64Xor(h1, k1)
		h1 = x64Rotl(h1, 27)
		h1 = x64Add(h1, h2)
		h1 = x64Add(x64Multiply(h1, [2]uint32{0, 5}), [2]uint32{0, 0x52dce729})
		k2 = x64Multiply(k2, c2)
		k2 = x64Rotl(k2, 33)
		k2 = x64Multiply(k2, c1)
		h2 = x64Xor(h2, k2)
		h2 = x64Rotl(h2, 31)
		h2 = x64Add(h2, h1)
		h2 = x64Add(x64Multiply(h2, [2]uint32{0, 5}), [2]uint32{0, 0x38495ab5})
	}
	k1 = [2]uint32{0, 0}
	k2 = [2]uint32{0, 0}
	switch remainder {
	case 15:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+14])}, 48))
		fallthrough
	case 14:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+13])}, 40))
		fallthrough
	case 13:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+12])}, 32))
		fallthrough
	case 12:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+11])}, 24))
		fallthrough
	case 11:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+10])}, 16))
		fallthrough
	case 10:
		k2 = x64Xor(k2, x64LeftShift([2]uint32{0, uint32(key[bytes+9])}, 8))
		fallthrough
	case 9:
		k2 = x64Xor(k2, [2]uint32{0, uint32(key[bytes+8])})
		k2 = x64Multiply(k2, c2)
		k2 = x64Rotl(k2, 33)
		k2 = x64Multiply(k2, c1)
		h2 = x64Xor(h2, k2)
		fallthrough
	case 8:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+7])}, 56))
		fallthrough
	case 7:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+6])}, 48))
		fallthrough
	case 6:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+5])}, 40))
		fallthrough
	case 5:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+4])}, 32))
		fallthrough
	case 4:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+3])}, 24))
		fallthrough
	case 3:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+2])}, 16))
		fallthrough
	case 2:
		k1 = x64Xor(k1, x64LeftShift([2]uint32{0, uint32(key[bytes+1])}, 8))
		fallthrough
	case 1:
		k1 = x64Xor(k1, [2]uint32{0, uint32(key[bytes])})
		k1 = x64Multiply(k1, c1)
		k1 = x64Rotl(k1, 31)
		k1 = x64Multiply(k1, c2)
		h1 = x64Xor(h1, k1)
	}
	h1 = x64Xor(h1, [2]uint32{0, uint32(len(key))})
	h2 = x64Xor(h2, [2]uint32{0, uint32(len(key))})
	h1 = x64Add(h1, h2)
	h2 = x64Add(h2, h1)
	h1 = x64Fmix(h1)
	h2 = x64Fmix(h2)
	h1 = x64Add(h1, h2)
	h2 = x64Add(h2, h1)
	return fmt.Sprintf("%08x%08x%08x%08x", h1[0], h1[1], h2[0], h2[1])
}
