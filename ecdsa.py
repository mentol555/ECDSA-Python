import math
import random
from hashlib import sha256


# secp256k1 eliptikus görbe
class ECDSA:
    def __init__(self):
        # y^2 = x^3 + ax + b
        # egyutthatok
        self.a = 0
        self.b = 7
        # prim modulus
        self.p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        # nr of points
        self.q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        # generátor pont
        self.G = {
            "x":55066263022277343669578718895168534326250603453777594175500187360389116729240,
            "y":32670510020758816978083085130507043184471273380659243275938904335757337482424
        }

    # eliptikus görbe műveletek
    # Pont duplázás
    def double(self, point):
        #S = ((3*x1^2 + a) / 2*y1 )
        S = (3*point["x"]**2 + self.a) * pow((2*point["y"]),-1,self.p)
        # x = (S^2 - 2x1) mod p
        x = (S**2 - (2*point["x"])) % self.p
        # y = (S * (x1 - x) - y1) mod p
        y = (S*(point["x"] - x) - point["y"]) % self.p
        return {"x": x, "y": y}

    # Pont összeadás
    def add(self, point1, point2):
        # ha ugyanaz a ketto
        if point1 == point2:
            return self.double(point1)
        #S = (y1 - y2) / (x1 - x2) mod p
        S = (point1["y"] - point2["y"]) * pow(point1["x"]-point2["x"],-1,self.p)
        # x = ( S^2 - x1 - x2 ) mod p
        x = (S**2 - point1["x"] - point2["x"]) % self.p
        # y = (S*(x1-x)-y1) mod p
        y = (S * (point1["x"]-x) - point1["y"]) % self.p
        return {"x": x, "y": y}

    # Pont szorzása skalárral, Double and Add módszer
    def multiply(self, n, point):
        current = point
        for b in '{0:b}'.format(n)[1:]:
            current = self.double(current)
            if(int(b) != 0):
                current = self.add(current, point)
        return current

    # PK és SK generálása
    def keygen(self):
        # d, azaz SK kiszamitas
        SK = random.randint(1, self.q - 1)
        # B = d*G
        PK = self.multiply(SK, self.G)
        return SK, PK

    # Aláirás generálása
    # [r, s] pár
    def sign(self, SK, hash):
        k = random.randint(1, self.q-1)
        k = int(hex(k), 16)
        # r = (k*G)["x"] mod q
        r = (self.multiply(k, self.G)["x"]) % self.q
        s = ((hash + SK * r) * pow(k,-1,self.q)) % self.q
        return {"r": r, "s": s}

    # Aláírás ellenőrzése
    def verify(self, PK, signature, hash):
        # u1 = (s^-1 * hash) * G(gen point)
        u1 = self.multiply(pow(signature["s"], -1, self.q)*hash, self.G)
        # u2 = (s^-1 * r) * B(pub key)
        u2 = self.multiply((pow(signature["s"], -1, self.q) * signature["r"]), PK)
        u3 = self.add(u1, u2)
        print(u3)
        print(signature)
        return u3["x"] == signature["r"]


def main():
    message = "\nECDSA algoritmus: Eliptikus görbe műveletek, Kulcsgenerálás, Aláírás, Ellenőrzés\n"
    print(message)
    curve = ECDSA()
    SK, PK = curve.keygen()
    print("--------------------SK--------------------\n"+str(SK))
    print("--------------------PK--------------------\n"+str(PK))
    hash = sha256(message.encode('UTF-8')).hexdigest()
    hash = int(hash,16)
    print("-------------------hash-------------------\n"+str(hash)+"\n")
    signature = curve.sign(SK, hash)
    if(curve.verify(PK, signature, hash)):
        print("Signature is valid!")
    else:
        print("Signature is not valid!")

if __name__ == "__main__":
    main()



