#include <windows.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>

#define ID_WINDOW_MINIKEY_EDITCTL	50
#define ID_WINDOW_RAWKEY_EDITCTL	51
#define ID_WINDOW_WIFKEY_EDITCTL	52
#define ID_WINDOW_ADDR_EDITCTL		53
#define ID_WINDOW_GENERATE_BTN		54

#define WINDOW_WIDTH				500
#define WINDOW_HEIGHT				225

unsigned char base58[] = 
{
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
	'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
	'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

int is_valid_minikey(char *minikey)
{
	char *tmpbuf = (char *)malloc(sizeof(char) * (strlen(minikey) + 2));
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int ret;
	EVP_MD_CTX ctx;
	
	strcpy(tmpbuf, minikey);
	strcat(tmpbuf, "?");
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, tmpbuf, strlen(tmpbuf));
	EVP_DigestFinal(&ctx, hash, &ret);
	
	free(tmpbuf);
	
	// If hash is 0x00, return 1, else 0
	if(!hash[0]) return(1);
	else return(0);
}

int base58encode(char **base58str, unsigned char *data, int datalen)
{
	BN_CTX *bnctx;
	int i, ret, zeroes;
	BIGNUM *bndata, *tmp, *divisor;
	char *buf = (char *)malloc(sizeof(char) * (datalen * 5));	// Fix this
	
	for(i = 0, zeroes = 0; i < datalen; i++)
	{
		if(!data[i]) zeroes++;
		else break;
	}
	
	bnctx = BN_CTX_new();
	divisor = BN_new();
	tmp = BN_new();
	
	BN_dec2bn(&divisor, "58");
	bndata = BN_bin2bn(data, datalen, NULL);
	
	for(i = 0; !BN_is_zero(bndata); i++)
	{
		BN_div(bndata, tmp, bndata, divisor, bnctx);			// Is using bndata twice legal?
		BN_bn2bin(tmp, (unsigned char *)&ret);					// The modulus can't be more than 4 bytes
		buf[i] = base58[ret];
	}
	
	BN_CTX_free(bnctx);
	BN_free(divisor);
	BN_free(tmp);
	BN_free(bndata);
	
	while(zeroes--)
		buf[i++] = base58[0];
	
	// Earlier for loop tacked on one extra
	datalen = ret = (i - 1);
	
	*base58str = (char *)malloc(sizeof(char) * (i + 1));
	
	// Copy string in reverse
	for(i = 0; i <= datalen && ret >= 0; i++, ret--)
		(*base58str)[i] = buf[ret];
	
	// NULL terminate
	(*base58str)[i] = 0x00;
	
	// Cleanup and return
	free(buf);
	return(i);
}

/*
	Assumes privkey has enough room
	Does not check minikey for validity
	Expects minikey to be NULL terminated
	Returns length of private key (not NULL terminated)
*/

int minikey_to_private_key(char *minikey, unsigned char *privkey)
{
	EVP_MD_CTX ctx;
	unsigned int ret;
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
		return(-1);
	
	if(!EVP_DigestUpdate(&ctx, minikey, strlen(minikey)))
	{
		EVP_DigestFinal(&ctx, privkey, &ret);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, privkey, &ret);
	return(ret);
}

int private_key_to_wif(char **wifkey, unsigned char *privkey, int keylen)
{
	EVP_MD_CTX ctx;
	unsigned int ret;
	unsigned char *extkey, hash[EVP_MAX_MD_SIZE];
	
	// A Base58 private key is 50 characters
	extkey = (unsigned char *)malloc(sizeof(unsigned char) * (keylen + 50));
	
	// DOGE version/application byte is 0x1E
	extkey[0] = 0x1E + 128;
	memcpy(extkey + 1, privkey, keylen);
	
	// keylen is now the length of ext key
	keylen++;
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
	{
		free(extkey);
		return(-1);
	}
	
	if(!EVP_DigestUpdate(&ctx, extkey, keylen))
	{
		EVP_DigestFinal(&ctx, hash, &ret);
		free(extkey);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, hash, &ret);
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
	{
		free(extkey);
		return(-1);
	}
	
	if(!EVP_DigestUpdate(&ctx, hash, ret))
	{
		EVP_DigestFinal(&ctx, hash, &ret);
		free(extkey);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, hash, &ret);
	
	// Sanity check
	if(ret < 4)
	{
		free(extkey);
		return(-1);
	}
	
	memcpy(extkey + keylen, hash, 4);
	keylen += 4;
	
	return(base58encode(wifkey, extkey, keylen));
}

int ecdsa_get_pubkey(unsigned char **pubkey, unsigned char *rawprivkey, int keylen)
{
	BN_CTX *ctx;
	EC_KEY *privkey;
	const EC_GROUP *group;
	EC_POINT *pubkeypoint;
	BIGNUM *bnprivkey, *bnpubkey;
	
	bnprivkey = BN_bin2bn(rawprivkey, keylen, NULL);
	privkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	group = EC_KEY_get0_group(privkey);
	
	pubkeypoint = EC_POINT_new(group);
	EC_KEY_set_private_key(privkey, bnprivkey);
	
	ctx = BN_CTX_new();
	bnpubkey = BN_new();
	EC_POINT_mul(group, pubkeypoint, bnprivkey, NULL, NULL, ctx);
	bnpubkey = EC_POINT_point2bn(group, pubkeypoint, POINT_CONVERSION_UNCOMPRESSED, bnpubkey, ctx);
	
	*pubkey = (unsigned char *)malloc(sizeof(unsigned char) * (BN_num_bytes(bnpubkey) + 1));
	BN_bn2bin(bnpubkey, *pubkey);
	return(BN_num_bytes(bnpubkey));
}

int pubkey_to_address(char **address, unsigned char *pubkey, int keylen)
{
	int i, zeroes;
	EVP_MD_CTX ctx;
	unsigned int ret;
	unsigned char hash[EVP_MAX_MD_SIZE], tmp1[EVP_MAX_MD_SIZE], tmp2[EVP_MAX_MD_SIZE];
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, pubkey, keylen);
	EVP_DigestFinal(&ctx, hash, &ret);
	
	RIPEMD160(hash, ret, tmp1);
	
	// 0x1E version byte for Dogecoin main network
	tmp2[0] = 0x1E;
	memcpy(tmp2 + 1, tmp1, RIPEMD160_DIGEST_LENGTH);
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, tmp2, RIPEMD160_DIGEST_LENGTH + 1);
	EVP_DigestFinal(&ctx, hash, &ret);
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, hash, ret);
	EVP_DigestFinal(&ctx, tmp1, &ret);
	
	memcpy(tmp2 + RIPEMD160_DIGEST_LENGTH + 1, tmp1, 4);
	
	for(i = 0, zeroes = 0; tmp2[i] == 0x00; i++, zeroes++);
	
	base58encode(address, tmp2, RIPEMD160_DIGEST_LENGTH + 5);
	
	return(0);
}

// Candidate must be 32 or more chars
DWORD WINAPI GenerateThreadProc(char *Candidate)
{
	int i;
	unsigned char tmp;
		
	for(;;)
	{
		for(i = 0; i < 30; i++)
		{
			do
			{
				RAND_bytes(&tmp, 1);
				tmp /= (255 / (57 + 1));
			} while(tmp >= 58);
			
			Candidate[i] = base58[tmp];
		}
		
		Candidate[i] = 0x00;
		
		if(is_valid_minikey(Candidate)) break;
	}
	
	return(0);
}

typedef struct _Info
{
	HANDLE MyWaitObj, hGenerateThread;
	HWND hMiniKeyEditCtl;
	char *Minikey;
} Info;

#if defined __GNUC__
VOID CALLBACK GenerateCompleteCallback(PVOID CallbackInfo, BOOLEAN TimerOrWaitFired __attribute__ ((unused)))
#else
VOID CALLBACK GenerateCompleteCallback(PVOID CallbackInfo, BOOLEAN TimerOrWaitFired)
#endif
{
	Info *CInfo = (Info *)CallbackInfo;
	
	UnregisterWait(CInfo->MyWaitObj);
	CloseHandle(CInfo->hGenerateThread);
	SetWindowTextA(CInfo->hMiniKeyEditCtl, CInfo->Minikey);
	
	CloseHandle(CInfo->hGenerateThread);
	free(CInfo->Minikey);
	return;
}

LRESULT WINAPI MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HWND hMiniKeyEditCtl;
	
	switch(msg)
	{
		case WM_CREATE:
		{
			RECT MainWindowRect;
			HWND hRawKeyEditCtl, hWIFKeyEditCtl, hAddrEditCtl, hGenerateBtn;
			
			GetClientRect(hwnd, &MainWindowRect);
			
			hMiniKeyEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .20), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_MINIKEY_EDITCTL, GetModuleHandle(NULL), NULL);
			
			hRawKeyEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_READONLY, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .35), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_RAWKEY_EDITCTL, GetModuleHandle(NULL), NULL);
			
			hWIFKeyEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_READONLY, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .50), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_WIFKEY_EDITCTL, GetModuleHandle(NULL), NULL);
				
			hAddrEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_READONLY, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .65), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_ADDR_EDITCTL, GetModuleHandle(NULL), NULL);
				
			hGenerateBtn = CreateWindow(TEXT("BUTTON"), TEXT("Generate"), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
				(int)(MainWindowRect.right * .47), (int)(MainWindowRect.bottom * .80), 55, 30, hwnd,
				(HMENU)ID_WINDOW_GENERATE_BTN, GetModuleHandle(NULL), NULL);
			
			SendMessage(hMiniKeyEditCtl, EM_LIMITTEXT, (WPARAM)30, MAKELPARAM(FALSE, 0));
			SendMessage(hMiniKeyEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hRawKeyEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hWIFKeyEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hAddrEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hGenerateBtn, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
				
			return(FALSE);
		}
		case WM_COMMAND:
		{
			if((HIWORD(wParam) == BN_CLICKED) && (LOWORD(wParam) == ID_WINDOW_GENERATE_BTN))
			{
				char *Minikey;
				Info *CallbackInfo;
				HANDLE hGenerateThread;
				
				CallbackInfo = (Info *)malloc(sizeof(Info));
				Minikey = (char *)malloc(sizeof(char) * 32);
				hGenerateThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GenerateThreadProc, Minikey, 0, NULL);
				
				CallbackInfo->Minikey = Minikey;
				CallbackInfo->hGenerateThread = hGenerateThread;
				CallbackInfo->hMiniKeyEditCtl = GetDlgItem(hwnd, ID_WINDOW_MINIKEY_EDITCTL);
				RegisterWaitForSingleObject(&CallbackInfo->MyWaitObj, hGenerateThread, GenerateCompleteCallback, CallbackInfo, INFINITE, WT_EXECUTEONLYONCE);
				return(FALSE);
			}
			if((HIWORD(wParam) == EN_UPDATE) && (LOWORD(wParam) == ID_WINDOW_MINIKEY_EDITCTL))
			{
				char Temp[5], *Addr, *WIFKey, Minikey[32], ASCIIPrivKey[(EVP_MAX_MD_SIZE * 2) + 3];
				unsigned char *Pubkey, RawPrivkey[EVP_MAX_MD_SIZE];
				int i, ret;
				
				GetWindowText(GetDlgItem(hwnd, ID_WINDOW_MINIKEY_EDITCTL), Minikey, 31);
				
				if(!is_valid_minikey(Minikey))
				{
					SetWindowTextA(GetDlgItem(hwnd, ID_WINDOW_RAWKEY_EDITCTL), "Invalid minikey");
					SetWindowText(GetDlgItem(hwnd, ID_WINDOW_WIFKEY_EDITCTL), "Invalid minikey");
					SetWindowTextA(GetDlgItem(hwnd, ID_WINDOW_ADDR_EDITCTL), "Invalid minikey");
					return(FALSE);
				}
				
				ret = minikey_to_private_key(Minikey, RawPrivkey);
				
				ASCIIPrivKey[0] = 0x00;
				
				for(i = 0; i < ret; i++)
				{
					sprintf(Temp, "%x", RawPrivkey[i]);
					strcat(ASCIIPrivKey, Temp);
				}
				
				SetWindowTextA(GetDlgItem(hwnd, ID_WINDOW_RAWKEY_EDITCTL), ASCIIPrivKey);
				
				// ret == length of RawPrivkey
				private_key_to_wif(&WIFKey, RawPrivkey, ret);
				SetWindowText(GetDlgItem(hwnd, ID_WINDOW_WIFKEY_EDITCTL), WIFKey);
				
				ret = ecdsa_get_pubkey(&Pubkey, RawPrivkey, ret);
				pubkey_to_address(&Addr, Pubkey, ret);
				SetWindowTextA(GetDlgItem(hwnd, ID_WINDOW_ADDR_EDITCTL), Addr);
				
				return(FALSE);
			}
			else
			{
				return(DefWindowProc(hwnd, msg, wParam, lParam));
			}
		}
		case WM_CLOSE:
		{
			DestroyWindow(hwnd);
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			break;
		}
		default:
			return(DefWindowProc(hwnd, msg, wParam, lParam));
	}
	return(0);
}

#ifdef __GNUC__
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance __attribute__ ((unused)), LPSTR lpCmdLine __attribute__ ((unused)), INT nCmdShow)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
#endif
{
	WNDCLASSEX wc;
	HWND hwnd;
	MSG msg;
	
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = MainWndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)GetStockObject(LTGRAY_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = TEXT("Window");
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	
	RegisterClassEx(&wc);
	
	hwnd = CreateWindow(TEXT("Window"), TEXT("Minikey Generator"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
		CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT, NULL, NULL, hInstance, NULL);
	
	SendMessage(hwnd, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	
	// If GetMessage() fails it returns -1,
	// so use > 0 for the check.
	while(GetMessage(&msg, NULL, 0, 0) > 0)
	{
		if(!IsDialogMessage(hwnd, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	
	return((int)msg.wParam);
}