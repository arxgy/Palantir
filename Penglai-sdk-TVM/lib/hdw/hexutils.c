#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hexutils.h"


void StrToHex(unsigned char *pbDest, char *pszSrc, int nLen)
{
	char h1, h2;
	unsigned char  s1, s2;
	for (int i = 0; i < nLen; i++)
	{
		h1 = pszSrc[2 * i];
		h2 = pszSrc[2 * i + 1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
			s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;

		pbDest[i] = s1 * 16 + s2;
	}
}

void HexToStr(char *pszDest, unsigned char *pbSrc, int nLen)
{
	char	ddl, ddh;
	for (int i = 0; i < nLen; i++)
	{
		ddh = 48 + pbSrc[i] / 16;
		ddl = 48 + pbSrc[i] % 16;
		if (ddh > 57) ddh = ddh + 7;
		if (ddl > 57) ddl = ddl + 7;
		pszDest[i * 2] = ddh;
		pszDest[i * 2 + 1] = ddl;
	}

	pszDest[nLen * 2] = '\0';
}

int ishex(char ch)
{
	if (ch >= '0' && ch <= '9')
		return 1;
	if (ch >= 'A' && ch <= 'F')
		return 1;
	if (ch >= 'a' && ch <= 'f')
		return 1;
	return 0;
}

void printHexData(char * loghea,unsigned char  *pData, int nLen) {
	unsigned char *msg =  malloc(nLen * 2 + 1);
	memset(msg, 0, nLen * 2 + 1);
	HexToStr((char *)msg, pData, nLen);
	printf("%s = %s ,len = %d \n",loghea,msg,nLen * 2);
	free(msg);
	printf("\n");
}
