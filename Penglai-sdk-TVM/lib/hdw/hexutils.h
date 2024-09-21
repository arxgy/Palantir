#ifndef __HEXUTILS_H__
#define __HEXUTILS_H__

void StrToHex(unsigned char *pbDest, char *pszSrc, int nLen);
void HexToStr(char *pszDest, unsigned char *pbSrc, int nLen);
int ishex(char ch);
void  inttohex(char * buf, int aa);
void printHexData(char * loghea, unsigned char  *pData, int nLen);
#endif
