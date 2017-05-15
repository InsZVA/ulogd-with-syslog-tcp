
// These functions append a string to a current buffer and change the current buffer
// point to the end. The destination is to improve the performance of Sprintf.
void appendStr(char** pDstStr, char* srcStr) {
	while (*(*pDstStr)++ = *srcStr++);
	(*pDstStr)--;
}

void appendUint(char** pDstStr, unsigned int n) {
	int num = n;
	int digits = 0;
	while (num) {
		num /= 10;
		(*pDstStr)++;
	}
	while (n) {
        int digit = n % 10;
        *(--(*pDstStr)) = "0123456789"[digit];
        n >>= 10;
    }
    return (*pDstStr);
}

void appendHEX8(char** pDstStr, int n) {
	int i = 0;
	for (; i < 8; i++)
		*((*pDstStr)++) = "0123456789ABCDEF"[(n >> ((7 - i) << 2)) & 0xf];
	return --(*pDstStr);
}

void appendHex8(char** pDstStr, int n) {
	int i = 0;
	for (; i < 8; i++)
		*((*pDstStr)++) = "0123456789abcdef"[(n >> ((7 - i) << 2)) & 0xf];
	return --(*pDstStr);
}

void appendHEX2(char** pDstStr, int n) {
	*((*pDstStr)++) = "0123456789ABCDEF"[(n >> 4) & 0xf];
	*((*pDstStr)++) = "0123456789ABCDEF"[n & 0xf];
	return --(*pDstStr);
}


void appendHex2(char** pDstStr, int n) {
	*((*pDstStr)++) = "0123456789abcdef"[n >> 4];
	*((*pDstStr)++) = "0123456789abcdef"[n & 0xf];
	return --(*pDstStr);
}

void appendHex(char** pDstStr, int n) {
	int num = n;
	int digits = 0;
	while (num) {
		num >>= 4;
		(*pDstStr)++;
	}
	while (n) {
        int digit = n & 0xf;
        *(--(*pDstStr)) = "0123456789abcdef"[digit];
        n >>= 4;
    }
    return (*pDstStr);
}
