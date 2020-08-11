import ctypes
from ctypes import c_byte, c_char_p, c_int, c_size_t, Structure, POINTER


class StokenBruteForceAssist(Structure):
    _fields_ = [
        ("pin", c_byte * 16),
        ("seed", c_byte * 16),
        ("code_out", c_byte * 16),
        ("time_blocks", c_byte * (16 * 5)),
        ("digits", c_int),
        ("key_time_offset", c_int),
    ]

    @property
    def code_out_str(self):
        s = bytes(self.code_out)
        return s[: s.find(0)].decode("ascii")


bfasst = ctypes.cdll.LoadLibrary("./libstoken_bfasst.so")
bfasst.stoken_bfasst_generate_passcode.argtypes = [POINTER(StokenBruteForceAssist)]

bfasst.stoken_bfasst_search_seed.argtypes = [
    POINTER(StokenBruteForceAssist),
    c_char_p,  # wanted_code
    POINTER(c_byte),  # 16-byte seeds
    c_size_t,  # seed count
    POINTER(c_size_t),  # index of successful seed
]


def main():
    ass = StokenBruteForceAssist()
    ass.pin[:5] = b"1234\0"
    ass.digits = 8
    ass.key_time_offset = 0
    ass.seed[:] = b"x" * 16
    ass.time_blocks[: 16 * 5] = b"y" * (16 * 5)
    ret = bfasst.stoken_bfasst_generate_passcode(ass)
    if ret != 0:
        raise ValueError("bad return code {}".format(ret))
    if ass.code_out_str != "26302029":
        raise ValueError("bad output code")

    buf = bytearray(b"abcdefgh" * 10000)
    pos = 16 * 777
    buf[pos : pos + 16] = b"x" * 16
    ass.seed[:] = b"\0" * 16
    out_index = c_size_t(-1)
    seeds_count = len(buf) // 16

    buf_type = ctypes.c_byte * len(buf)

    ret = bfasst.stoken_bfasst_search_seed(
        ass, b"26302029\0", buf_type.from_buffer(buf), seeds_count, out_index
    )
    if ret != 0:
        raise ValueError("bad return code {}".format(ret))
    if out_index.value != pos // 16:
        raise AssertionError(
            "did not find seed; expected {}, got {}".format(pos // 16, out_index.value)
        )

    print("all good")


if __name__ == "__main__":
    main()
