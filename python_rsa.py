from dataclasses import dataclass
import random


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def is_prime(integer: int | bytes) -> bool:
    if type(integer) is bytes:
        integer = int.from_bytes(integer)
    elif type(integer) is str:
        integer = int(integer)
    elif type(integer) is not int:
        raise ValueError("argument must be an integer or bytes!")

    if integer == 2:
        return True
    for _ in range(100):
        a = int((random.random() % (integer - 2)) + 2)
        if gcd(a, integer) != 1:
            return False
        if pow(a, integer - 1, integer) != 1:
            return False
    return True


def generate_prime_pare(k: int) -> tuple[int, int]:
    integer = random.getrandbits(k)
    il, ir = integer, integer
    if il % 2 == 0:
        il -= 1
    if ir % 2 == 0:
        ir += 1
    while not is_prime(ir) or not is_prime(il):
        il -= 2
        ir += 2
    return il, ir


@dataclass
class RsaData:
    Primes: tuple[int, int] = None
    Euler: int = None
    Exponent: int = None
    Pubkey: tuple[int, int] = None
    PrivateKey: tuple[int, int] = None


class RSA:
    def __init__(self, **kwargs) -> None:
        self._data = RsaData()
        self.key_length = kwargs.get('key_length', 64)
        self.chunk_size = kwargs.get('chunk_size', 8)
        self._multiply_chunk = self.key_length // 32

    def generate(self) -> None:
        while True:
            self._data.Primes = generate_prime_pare(self.key_length)
            prime1, prime2 = self._data.Primes
            self._data.Euler = (prime1 - 1) * (prime2 - 1)
            self._data.Exponent = self._get_exponent()
            if self._data.Exponent is None:
                continue
            self._data.Pubkey = (self._data.Exponent, prime1 * prime2)
            self._data.PrivateKey = (self._get_private_key(), prime1 * prime2)
            if self._data.PrivateKey is None:
                continue
            break

    def encode(self, data: str) -> bytes:
        data = data.encode('utf-8')

        if len(data) % self.chunk_size != 0:
            data += b'\0' * (len(data) % self.chunk_size)

        encoded_data = b""
        for i in range(0, len(data), self.chunk_size):
            _data = data[i:i + self.chunk_size]
            _data_in_int = int.from_bytes(_data, 'big')
            _encoded_data = pow(
                _data_in_int, self._data.Pubkey[0], self._data.Pubkey[1])
            encoded_data += _encoded_data.to_bytes(
                self.chunk_size * self._multiply_chunk, 'big')
        return encoded_data

    def decode(self, data: bytes) -> str:
        decoded = b""
        for i in range(0, len(data), self.chunk_size * self._multiply_chunk):
            _data = data[i:i + self.chunk_size * self._multiply_chunk]
            _data_in_int = int.from_bytes(_data, 'big')
            _decoded_data = pow(
                _data_in_int, self._data.PrivateKey[0], self._data.PrivateKey[1])
            decoded += (_decoded_data.to_bytes(self.chunk_size * self._multiply_chunk, 'big')
                        .replace(b"\00", b""))
        return decoded.decode('utf-8')

    def _get_private_key(self) -> int | None:
        if gcd(self._data.Exponent, self._data.Euler) != 1:
            return None
        u1, u2, u3 = 1, 0, self._data.Exponent
        v1, v2, v3 = 0, 1, self._data.Euler
        while v3 != 0:
            q = u3 // v3  # // is the integer division operator
            v1, v2, v3, u1, u2, u3 = (
                u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % self._data.Euler

    def _get_exponent(self) -> int | None:
        prime1, prime2 = self._data.Primes
        for i in range(prime1 * prime2 % self._data.Euler, self._data.Euler, 2):
            if gcd(i, self._data.Euler) == 1:
                return i
        return None


if __name__ == "__main__":
    rsa = RSA(key_length=512)
    rsa.generate()

    x = rsa.encode("test")

    print('Encoded:', x)

    x = rsa.decode(x)

    print("Decoded:", x)
