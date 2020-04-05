from random import randint

class RSAClient:
    __myascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*() -_=+/,.<>{};:'\"\\" + chr(11)
    def __init__(self, keys = None):
        if keys is None:
            self.publicKey, self.privateKey =  self.__GenerateKeys()
        else:
            self.publicKey, self.privateKey =  keys
    def GetPublicKey(self) -> tuple:
        return self.publicKey
    def GetTargetPublicKey(self) -> tuple:
        return self.__targetPublicKey
    def SetTargetPublicKey(self, foreignPublicKey : tuple) -> None:
        self.__targetPublicKey = foreignPublicKey
    def EncodeMessage(self, message : str) -> []:
        message = self.__MessageToInt(message)
        e, n = self.__targetPublicKey
        message = [self.__Modular_pow(ms, e, n) for ms in message]
        return message
    def DecodeForeignMessage(self, message : []) -> str:
        d, n = self.privateKey 
        message = [self.__Modular_pow(ms, d, n) for ms in message] 
        return self.__IntToMassage(message)
    def __MessageToInt(self, message : str) -> []:
        if(len(message) % 2 != 0):
            message = message + chr(11)
        segments = [message[i:i+4] for i in range(0, len(message), 4)]
        return [self.__SegmentToInt(seg) for seg in segments]
    def __SegmentToInt(self, segment : str) -> int:
        sum = 0
        for i in range(len(segment)):
            key = self.__myascii.find(segment[::-1][i])
            sum += key*len(self.__myascii)**i
        return sum
    def __IntToMassage(self, numbers : [] ) -> str:
       message = ''.join([self.__IntToSegment(num) for num in numbers])
       if(message[-1] == chr(11)):
           message = message[:-1]
       return message
    def __IntToSegment(self, number : int) -> str:
        r = 0
        text = ''
        while(number != 0):
            r = number % len(self.__myascii)
            number //= len(self.__myascii)
            text = text + self.__myascii[r]
        if(len(text) % 2 != 0):
            text = text + 'A'
        return text[::-1]
    def __Modular_pow(self, a: int, t : int, n : int) -> int:
        rev_bin_t = bin(t).split('b')[1][::-1]
        x = 1
        for i in range(1, len(rev_bin_t) + 1):
            if(rev_bin_t[i-1] == "1"):
                x = x * a % n
            a = a * a % n
        return x
    def __Find_big_prime(self, min : int, max: int) -> int:
        for num in range(min, max):
            for i in range(2, num//2):
                if (num % i) == 0:
                    break
            else:
                return num
    def __Random_big_prime(self) -> int:
        #min, max = 2**1024, 2**1025 <- It takes to long. I'm searching to finding big primes in another way.
        min, max = 2**20, 2**21
        min = min + randint(1, max - min // 2)
        return self.__Find_big_prime(min, max)
    def __Extended_Euclidean(self, n : int, a : int) -> (int, int):
        if(a > n):
            a, n = n, a
        q,r = n // a, n % a
        U, U_, V, V_ = 0, 1, 1, 0
        while(r != 0):
            q,r = n // a, n % a
            n, a = a, r 
            U, U_ = U_ - q*U, U
            V, V_ = V_ - q*V, V
        return V_, n
    def __IsGCDOne(self,a : int, b : int) -> bool:
        return self.__Extended_Euclidean(a, b)[1] == 1
    def __GenerateKeys(self)-> (tuple, tuple):
        p, q = self.__Random_big_prime(), self.__Random_big_prime()
        while(p == q or p is None or q is None):
            p, q = self.__Random_big_prime(), self.__Random_big_prime()
        n, phi = p * q, (p - 1)*(q - 1)
        e = randint(2, phi - 1)
        gcdOne = self.__IsGCDOne(e, phi)
        while( not gcdOne):
            e = randint(2, phi - 1)
            gcdOne = self.__IsGCDOne(e, phi)
        d = self.__Extended_Euclidean(phi, e)[0] % phi
        return (e, n), (d, n)

#Example of usage 
if __name__ == "__main__":
    Bob, Alice, Charlie = RSAClient(), RSAClient(), RSAClient()
    Bob.SetTargetPublicKey(Alice.GetPublicKey())
    messageToAlice = input("Bob message: ")
    EncodedBobMessage = Bob.EncodeMessage(messageToAlice)
    print(f"Encoded message: {EncodedBobMessage}")
    messageFromBob = Alice.DecodeForeignMessage(EncodedBobMessage)
    print(f'Alice received: {messageFromBob}')
