package encryptions

func CalculateMd5_b64(b string) string {
	return md5_binl2b64(Md5CMC5(Md5_s2b(b), len(b)*8))
}

// Funções auxiliares
func md5SafeAdd(g, a int) int {
	b := (g & 65535) + (a & 65535)
	h := (g >> 16) + (a >> 16) + (b >> 16)
	return (h << 16) | (b & 65535)
}

func md5BitRol(a, b int) int {
	return (a << b) | (a >> (32 - b))
}

func md5Cmn(a, j, k, m, b, i int) int {
	return md5SafeAdd(md5BitRol(md5SafeAdd(md5SafeAdd(j, a), md5SafeAdd(m, i)), b), k)
}

func md5FF(m, o, a, b, p, c, d int) int {
	return md5Cmn((o&a)|((^o)&b), m, o, p, c, d)
}

func md5GG(m, o, a, b, p, c, d int) int {
	return md5Cmn((o&b)|(a&^b), m, o, p, c, d)
}

func md5HH(m, o, a, b, p, c, d int) int {
	return md5Cmn(o^a^b, m, o, p, c, d)
}

func md5II(m, o, a, b, p, c, d int) int {
	return md5Cmn(a^(o|^b), m, o, p, c, d)
}

// Função principal
func Md5CMC5(g []int, a int) []int {
	if len(g) != (((a+64)>>9)<<4)+14 {
		for i := len(g); i < (((a+64)>>9)<<4)+15; i++ {
			if i == (((a+64)>>9)<<4)+14 {
				g = append(g, a)
			} else if i == a>>5 {
				g = append(g, 0)
				g[a>>5] |= 128 << ((a) % 32)
			} else {
				g = append(g, 0)
			}
		}
	}

	if len(g) != (((a+64)>>9)<<4)+14 {
		for i := len(g); i < (((a+64)>>9)<<4)+15; i++ {
			if i == (((a+64)>>9)<<4)+14 {
				g = append(g, a)
			} else {
				g = append(g, 0)
			}
		}
	}

	h := 1732584193
	i := -271733879
	j := -1732584194
	y := 271733878

	for e := 0; e < len(g); e += 16 {
		b, c, d, f := h, i, j, y

		h = md5FF(h, i, j, y, g[e+0], 7, -680876936)
		y = md5FF(y, h, i, j, g[e+1], 12, -389564586)
		j = md5FF(j, y, h, i, g[e+2], 17, 606105819)
		i = md5FF(i, j, y, h, g[e+3], 22, -1044525330)
		h = md5FF(h, i, j, y, g[e+4], 7, -176418897)
		y = md5FF(y, h, i, j, g[e+5], 12, 1200080426)
		j = md5FF(j, y, h, i, g[e+6], 17, -1473231341)
		i = md5FF(i, j, y, h, g[e+7], 22, -45705983)
		h = md5FF(h, i, j, y, g[e+8], 7, 1770035416)
		y = md5FF(y, h, i, j, g[e+9], 12, -1958414417)
		j = md5FF(j, y, h, i, g[e+10], 17, -42063)
		i = md5FF(i, j, y, h, g[e+11], 22, -1990404162)
		h = md5FF(h, i, j, y, g[e+12], 7, 1804603682)
		y = md5FF(y, h, i, j, g[e+13], 12, -40341101)
		j = md5FF(j, y, h, i, g[e+14], 17, -1502002290)
		i = md5FF(i, j, y, h, 0, 22, 1236535329)
		h = md5GG(h, i, j, y, g[e+1], 5, -165796510)
		y = md5GG(y, h, i, j, g[e+6], 9, -1069501632)
		j = md5GG(j, y, h, i, g[e+11], 14, 643717713)
		i = md5GG(i, j, y, h, g[e+0], 20, -373897302)
		h = md5GG(h, i, j, y, g[e+5], 5, -701558691)
		y = md5GG(y, h, i, j, g[e+10], 9, 38016083)
		j = md5GG(j, y, h, i, 0, 14, -660478335)
		i = md5GG(i, j, y, h, g[e+4], 20, -405537848)
		h = md5GG(h, i, j, y, g[e+9], 5, 568446438)
		y = md5GG(y, h, i, j, g[e+14], 9, -1019803690)
		j = md5GG(j, y, h, i, g[e+3], 14, -187363961)
		i = md5GG(i, j, y, h, g[e+8], 20, 1163531501)
		h = md5GG(h, i, j, y, g[e+13], 5, -1444681467)
		y = md5GG(y, h, i, j, g[e+2], 9, -51403784)
		j = md5GG(j, y, h, i, g[e+7], 14, 1735328473)
		i = md5GG(i, j, y, h, g[e+12], 20, -1926607734)
		h = md5HH(h, i, j, y, g[e+5], 4, -378558)
		y = md5HH(y, h, i, j, g[e+8], 11, -2022574463)
		j = md5HH(j, y, h, i, g[e+11], 16, 1839030562)
		i = md5HH(i, j, y, h, g[e+14], 23, -35309556)
		h = md5HH(h, i, j, y, g[e+1], 4, -1530992060)
		y = md5HH(y, h, i, j, g[e+4], 11, 1272893353)
		j = md5HH(j, y, h, i, g[e+7], 16, -155497632)
		i = md5HH(i, j, y, h, g[e+10], 23, -1094730640)
		h = md5HH(h, i, j, y, g[e+13], 4, 681279174)
		y = md5HH(y, h, i, j, g[e+0], 11, -358537222)
		j = md5HH(j, y, h, i, g[e+3], 16, -722521979)
		i = md5HH(i, j, y, h, g[e+6], 23, 76029189)
		h = md5HH(h, i, j, y, g[e+9], 4, -640364487)
		y = md5HH(y, h, i, j, g[e+12], 11, -421815835)
		j = md5HH(j, y, h, i, 0, 16, 530742520)
		i = md5HH(i, j, y, h, g[e+2], 23, -995338651)
		h = md5II(h, i, j, y, g[e+0], 6, -198630844)
		y = md5II(y, h, i, j, g[e+7], 10, 1126891415)
		j = md5II(j, y, h, i, g[e+14], 15, -1416354905)
		i = md5II(i, j, y, h, g[e+5], 21, -57434055)
		h = md5II(h, i, j, y, g[e+12], 6, 1700485571)
		y = md5II(y, h, i, j, g[e+3], 10, -1894986606)
		j = md5II(j, y, h, i, g[e+10], 15, -1051523)
		i = md5II(i, j, y, h, g[e+1], 21, -2054922799)
		h = md5II(h, i, j, y, g[e+8], 6, 1873313359)
		y = md5II(y, h, i, j, 0, 10, -30611744)
		j = md5II(j, y, h, i, g[e+6], 15, -1560198380)
		i = md5II(i, j, y, h, g[e+13], 21, 1309151649)
		h = md5II(h, i, j, y, g[e+4], 6, -145523070)
		y = md5II(y, h, i, j, g[e+11], 10, -1120210379)
		j = md5II(j, y, h, i, g[e+2], 15, 718787259)
		i = md5II(i, j, y, h, g[e+9], 21, -343485551)
		h = md5SafeAdd(h, b)
		i = md5SafeAdd(i, c)
		j = md5SafeAdd(j, d)
		y = md5SafeAdd(y, f)
	}

	return []int{h, i, j, y}
}

func Md5_s2b(c string) []int {
	a := (1 << 8) - 1                    // 255
	h := make([]int, ((len(c)+3)/4)*4/4) // Inicializa o slice corretamente
	for b := 0; b < len(c)*8; b += 8 {
		h[b>>5] |= int(c[b/8]&byte(a)) << (b % 32)
	}
	return h
}

// func md5_s2b(c string) []int {
// 	h := make([]int, (len(c)*8+31)/32) // Inicializa o slice com tamanho suficiente
// 	mask := (1 << 8) - 1               // Máscara para 8 bits (255)

// 	for b := 0; b < len(c)*8; b += 8 {
// 		char := int(c[b/8])                  // Obtém o caractere como inteiro
// 		h[b>>5] |= (char & mask) << (b % 32) // Alinha e adiciona ao índice apropriado
// 	}

// 	return h
// }

func md5_binl2b64(i []int) string {
	c := ""
	j := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	p := ""

	for b := 0; b < len(i)*4; b += 3 {
		var a int

		// Protege contra índices fora do intervalo
		if b>>2 < len(i) {
			a |= ((i[b>>2] >> 8 * (b % 4)) & 255) << 16
		}
		if (b+1)>>2 < len(i) {
			a |= ((i[(b+1)>>2] >> 8 * ((b + 1) % 4)) & 255) << 8
		}
		if (b+2)>>2 < len(i) {
			a |= (i[(b+2)>>2] >> 8 * ((b + 2) % 4)) & 255
		}

		for d := 0; d < 4; d++ {
			if b*8+d*6 > len(i)*32 {
				p += c
			} else {
				p += string(j[(a>>6*(3-d))&63])
			}
		}
	}

	return p
}
