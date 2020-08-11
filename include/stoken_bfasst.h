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
  char pin[16];
  char seed[16];
  char code_out[16];
  char time_blocks[16 * STOKEN_TIME_BLOCK_COUNT];
  int digits;
  int key_time_offset;
};

STOKEN_BFASST_API int
stoken_bfasst_generate_passcode(struct StokenBruteForceAssist *assist);
