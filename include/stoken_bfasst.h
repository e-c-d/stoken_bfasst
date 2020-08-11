#include <string.h>
#include <inttypes.h>

#ifdef _WIN32
#    ifdef STOKEN_BFASST_EXPORTS
#        define STOKEN_BFASST_API __declspec(dllexport)
#    else
#        define STOKEN_BFASST_API __declspec(dllimport)
#    endif
#else
#    define STOKEN_BFASST_API
#endif

#define STOKEN_TIME_BLOCK_COUNT 5

struct StokenBruteForceAssist {
  unsigned char pin[16];
  unsigned char seed[16];
  unsigned char code_out[16];
  unsigned char time_blocks[16 * STOKEN_TIME_BLOCK_COUNT];
  int digits;
  int key_time_offset;
};

STOKEN_BFASST_API int
stoken_bfasst_generate_passcode(struct StokenBruteForceAssist *assist);
