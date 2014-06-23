/*
	scexec - Portable utility to execute in memory a sequence of opcodes
	Vlatko Kosturjak, vlatko.kosturjak@gmail.com
	Based on Bernardo Damele A. G. shellcodeexecute
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* Microsoft Visual Studio have different way of specifying variable number of args */
#ifdef DEBUG
 #ifdef _MSC_VER
 #define DEBUG_PRINTF(fmt, ...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
 #else
 #define DEBUG_PRINTF(fmt, args...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##args)
 #endif
#else
 #ifdef _MSC_VER
 #define DEBUG_PRINTF(fmt, ...)
 #else
 #define DEBUG_PRINTF(fmt, args...)
 #endif
#endif

#ifdef __MINGW32__
#define _WIN32_WINNT 0x502 
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
DWORD WINAPI exec_payload(LPVOID lpParameter);
	#if defined(_WIN64)
	void __exec_payload(LPVOID);
	static DWORD64 handler_eip;
	#else
	static DWORD handler_eip;
	#endif
#else
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef CALL_FIRST
#define CALL_FIRST 1 
#endif

#define ENCBASE64 1 
#define ENCUUENC 2

#define ARGINPUT 0
#define FILEINPUT 1

#define EXESTD 0
#define EXEEAX 1

static char base64_decoding_table[] = {
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x00,
0x00,0x00,0x3f,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
0x19,0x00,0x00,0x00,0x00,0x00,0x00,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,
0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00
};

int payloadenc=0;
int executetype=0;
int scinput=0;

unsigned char  *base64_decode(const unsigned char *data,
	      size_t input_length,
	      size_t * output_length)
{
	int		i = 0,	j = 0;
	unsigned int	sextet_a, sextet_b, sextet_c, sextet_d, triple;
	unsigned char  *decoded_data;

	if (input_length % 4 != 0)
		return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=')
		(*output_length)--;
	if (data[input_length - 2] == '=')
		(*output_length)--;

	decoded_data = malloc(*output_length);
	if (decoded_data == NULL)
		return NULL;

	for (i = 0, j = 0; i < input_length;) {

		sextet_a = data[i] == '=' ? 0 & i++ : base64_decoding_table[data[i++]];
		sextet_b = data[i] == '=' ? 0 & i++ : base64_decoding_table[data[i++]];
		sextet_c = data[i] == '=' ? 0 & i++ : base64_decoding_table[data[i++]];
		sextet_d = data[i] == '=' ? 0 & i++ : base64_decoding_table[data[i++]];

		triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length)
			decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length)
			decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length)
			decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

int isblanks(int c) {
	if (c == '\t' || c == '\n' || c == '\r' || c == ' ')
		return 1;
	return 0;
}

unsigned decode_char(unsigned char in) {
	return ((in) - ' ') & 63;
}

int uudecode(unsigned char *input, int offset, unsigned char *output) {
	int		ooffset = 0;
	while (input[offset] != 32 && input[offset] != '\0') {
		int		encodedoctets;
		encodedoctets = decode_char(input[offset]);
		for (++offset; encodedoctets > 0; offset += 4, encodedoctets -= 3) {
			char		ch;
			if (encodedoctets >= 3) {
				ch = decode_char(input[offset]) << 2 |
					decode_char(input[offset + 1]) >> 4;
				output[ooffset++] = ch;
				ch = decode_char(input[offset + 1]) << 4 |
					decode_char(input[offset + 2]) >> 2;
				output[ooffset++] = ch;
				ch = decode_char(input[offset + 2]) << 6 |
					decode_char(input[offset + 3]);
				output[ooffset++] = ch;
			} else {
				if (encodedoctets >= 1) {
					ch = decode_char(input[offset]) << 2 |
						decode_char(input[offset + 1]) >> 4;
					output[ooffset++] = ch;
				}
				if (encodedoctets >= 2) {
					ch = decode_char(input[offset + 1]) << 4 |
						decode_char(input[offset + 2]) >> 2;
					output[ooffset++] = ch;
				}
			}
		}
		while (isblanks(input[offset]))
			offset++;
	}
	while (isblanks(input[offset]))
		offset++;
	return ooffset;
}

int sys_bineval(unsigned char *argv, size_t len);
void call_handler (void *payload);

int parseargs (char *params) {
	int i=0;
	DEBUG_PRINTF("Using params: %s\n", params);
	while (params[i]!='\0') {
		switch (params[i]) {
			case 'b':
				payloadenc=ENCBASE64;
				break;
			case 'u':
				payloadenc=ENCUUENC;
				break;
			case 'a':
				executetype=EXEEAX;
				break;
			case 'f':
				scinput=FILEINPUT;
				break;
			default:
				DEBUG_PRINTF("Wrong parm: %c\n", params[i]);
		} /* switch */
		i++;
	} /* while not null byte  */\
	return (i);
}

int main(int argc, char *argv[])
{
	FILE *f;
	long fsize;
	unsigned char *fcontent;
	size_t len;

	if (argc < 2) {
		printf("Run:\n\t%s <alphanumeric-encoded shellcode>\n",argv[0]);
		exit(-1);
	}
	if (argc < 3) {
		/* assume alphanumeric shellcode */
		executetype=EXEEAX;
		len = (size_t)strlen(argv[1]);
		sys_bineval(argv[1], len);
	} else {
		/* parse params */
		parseargs(argv[1]);

		if (scinput == FILEINPUT) {
			f = fopen(argv[2], "rb");
			if (f==NULL) {
				DEBUG_PRINTF("Cannot open file for reading: %s\n", argv[2]);
				exit(0);
			}
			fseek(f, 0, SEEK_END);
			fsize = ftell(f);
			fseek(f, 0, SEEK_SET);

			fcontent = malloc(fsize + 1);
			if (fcontent==NULL) {
				DEBUG_PRINTF("Error allocating memory: %ld\n", fsize+1);
				fclose(f);
				exit(0);
			}
			fread(fcontent, fsize, 1, f);
			fclose(f);
			fcontent[fsize] = '\0';
			DEBUG_PRINTF("Read %ld bytes from %s\n", fsize, argv[2]);
			sys_bineval(fcontent, fsize);
			free (fcontent);
		} else {
			len = (size_t)strlen(argv[2]);
			sys_bineval(argv[2], len);
		}
	}

	exit(0);
}

int sys_bineval(unsigned char *buf, size_t len)
{
	size_t olen;
	unsigned char *argv=buf;
	unsigned char *tempbuf=NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	unsigned char *winmem;
#else
	int *pmem;
	size_t page_size;
	pid_t pID;
#endif

	DEBUG_PRINTF("Decoding shellcode\n");
	switch (payloadenc) {
		case ENCBASE64:
			DEBUG_PRINTF("Using base64\n");
			/* buf = input, ilen, outputlen */
			tempbuf=base64_decode(buf,len,&olen);
			DEBUG_PRINTF("Size of decoded data is: %ld\n", olen);
			argv=tempbuf;
			break;
		case ENCUUENC:
			DEBUG_PRINTF("Using uudecode\n");
			/* outputlen = inputdata,offset,outputdata */
			tempbuf=malloc(len+1);
			if (tempbuf==NULL) {
				DEBUG_PRINTF("Error allocating %ld for uudecode", len+1);
				return 0;
			}
			olen=uudecode(buf,0,tempbuf);
			DEBUG_PRINTF("Size of decoded data is: %ld\n", olen);
			argv=tempbuf;
			break;
		default:
			DEBUG_PRINTF("No decoding needed\n");
	}

	/* sanity check: pointer should point to sane address */	
	if (argv==NULL) {
		DEBUG_PRINTF("Pointer to shellcode is NULL\n");
		return 0;
	}	

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	// allocate a +rwx memory page
	DEBUG_PRINTF("Allocating RWX memory...\n");
	winmem = (char *) VirtualAlloc(NULL, len+1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy over the shellcode
	DEBUG_PRINTF("Copying shellcode\n");
	memcpy(winmem, argv, len+1);

	DEBUG_PRINTF("Freeing temporary buffer\n");
	if (tempbuf!=NULL) {
		free(tempbuf);
	}

	call_handler (winmem);

#else
	DEBUG_PRINTF("Performing fork...\n");
	pID = fork();
	if(pID<0)
		return 1;

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);	// align to page boundary

		// mmap an +rwx memory page
		DEBUG_PRINTF("Mmaping memory page (+rwx)\n");
		pmem = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

		if (pmem == MAP_FAILED)
			return 1;

		// copy over the shellcode
		DEBUG_PRINTF("Copying shellcode\n");
		memcpy(pmem, argv, len);

		// execute it
		DEBUG_PRINTF("Executing shellcode\n");
		((void (*)(void))pmem)();
	}

	if(pID>0)
		waitpid(pID, 0, WNOHANG);
#endif

	DEBUG_PRINTF("Returning from execute function\n");
	return 0;
}

/* if windows */
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32) 
void call_payload (void *payload) {
	int pID;

	/* execute it by ASM code defined in exec_payload function */
	DEBUG_PRINTF("Executing shellcode\n");
	if (executetype == EXEEAX) {
		DEBUG_PRINTF("Executing through call EAX\n");
		WaitForSingleObject(CreateThread(NULL, 0, exec_payload, payload, 0, &pID), INFINITE);
	}
	if (executetype == EXESTD) {
		DEBUG_PRINTF("Standard execute\n");
		(*(void (*)()) payload)();
	}
}

/* if mingw */
#ifdef __MINGW32__ 
LONG WINAPI VectoredHandler (struct _EXCEPTION_POINTERS *ExceptionInfo) {
	PCONTEXT Context;
	Context = ExceptionInfo->ContextRecord;
	DEBUG_PRINTF("Exception occured. Entered into Exception Handler.\n");
#ifdef _AMD64_
	Context->Rip = handler_eip;
#else
	Context->Eip = handler_eip;
#endif    
	DEBUG_PRINTF("Returning from Exception handler\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

void call_handler (void *payload) {
	/* exception handling */
	PVOID h;
	handler_eip = &&fail;

	DEBUG_PRINTF("Adding handler\n");
	h = AddVectoredExceptionHandler(CALL_FIRST,VectoredHandler);
	DEBUG_PRINTF("Executing payload\n");

	/* call real function */
	call_payload(payload);

fail:
	DEBUG_PRINTF("Removing handler\n");
	RemoveVectoredExceptionHandler(h);
}

DWORD WINAPI exec_payload(LPVOID lpParameter)
{
#if defined(_WIN64)
	DEBUG_PRINTF("Executing payload64\n");
	__asm__ (
		"mov %0, %%rax\n"
		"call *%%rax\n"
		: // no output
		: "m"(lpParameter) // input
	);
#else
	DEBUG_PRINTF("Executing payload32\n");
	__asm__ (
		"mov %0, %%eax\n"
		"call *%%eax\n"
		: // no output
		: "m"(lpParameter) // input
	);
#endif
	return(0);
}
#else /* MINGW */

void call_handler (void *payload) {
	__try
	{
		DEBUG_PRINTF("Executing payload via VC\n");
		call_payload(payload);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DEBUG_PRINTF("Exception occured. In VC exception Handler.\n");
	}
}

#if defined(_WIN64)
DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	DEBUG_PRINTF("Executing payload64 via VC\n");
	__exec_payload(lpParameter);
	return 0;
}
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	DEBUG_PRINTF("Executing payload32 via VC\n");
	__asm
	{
		mov eax, [lpParameter]
		call eax
	}
	return 0;
}
#endif /* _WIN64 */
#endif /* __MINGW__ */
#endif /* if windows */
