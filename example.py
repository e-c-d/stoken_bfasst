import ctypes
from ctypes import c_byte, c_int, Structure, POINTER


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


def main():
    ass = StokenBruteForceAssist()
    ass.pin[:5] = b"1234\0"
    ass.digits = 8
    ass.key_time_offset = 0
    ass.seed[:16] = b"x" * 16
    ass.time_blocks[: 16 * 5] = b"y" * (16 * 5)
    ret = bfasst.stoken_bfasst_generate_passcode(ass)
    if ret != 0:
        raise ValueError("bad return code {}".format(ret))
    if ass.code_out_str != "26302029":
        raise ValueError("bad output code")


if __name__ == "__main__":
    main()
