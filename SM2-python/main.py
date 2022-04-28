# encoding=utf-8
from EccClass import *
from CurveCollections import *

# curve = EllipticCurve("secp256k1", curves["secp256k1"].a, curves["secp256k1"].b, curves["secp256k1"].p,
#                       curves["secp256k1"].n, curves["secp256k1"].G)

curve = EllipticCurve("sm2", curves["sm2"].a, curves["sm2"].b, curves["sm2"].p, curves["sm2"].n, curves["sm2"].G)


# 求value在Fp域的逆——用于分数求逆
def get_gcd(number_a, number_b, v):
    """
    求两个数的最大公约数，顺带能求number_a mod number_b的逆元

    Args:
        number_a (int): 第一个整数
        number_b (int): 第二个整数
        v (list): list指针，可用以存放求 number_a相对于number_b的逆元 时的迭代的中间结果

    Returns:number_x与number_y的最大公约数

    """
    if (number_b == 0):
        v[0] = 1
        v[1] = 0
        return number_a

    r = get_gcd(number_b, number_a % number_b, v)

    temp = v[1]
    v[1] = v[0] - (number_a // number_b) * v[1]
    v[0] = temp
    return r


def get_inverse(number_a, number_b):
    """
    求number_a相对于模数number_b的乘法逆元

    Args:
        number_a (int):     待求逆元的整数
        number_b (int):     模数

    Returns:    number_a的逆元

    """
    v = [0, 0]
    r = get_gcd(number_a, number_b, v)
    if (v[0] < 0):
        v[0] = number_b - abs(v[0])
    return v[0]


def get_remainder(number, modulus):
    """

    Args:
        number (int):
        modulus (int):

    Returns (int):

    """
    return number % modulus


# 计算P+Q函数
def add_p_q(dot_p, dot_q):
    """
    求两个EccDot点相加的结果，分为两种情况dot_p==dot_q和dot_p！=dot_q

    Args:
        dot_p (EccDot): 第一个EccDot点
        dot_q (EccDot): 第二个EccDot点

    Returns:两个点相加的结果EccDot点

    """
    # 若P = Q，则k=[(3x1^2+a)/2y1]mod p
    if dot_p.x == dot_q.x and dot_p.y == dot_q.y:
        molecule_k = 3 * (dot_p.x * dot_p.x) + curve.a  # 计算分子
        denominator_k = 2 * dot_p.y  # 计算分母
    # 若P≠Q，则k=(y2-y1)/(x2-x1) mod p
    else:
        molecule_k = dot_q.y - dot_p.y
        denominator_k = dot_q.x - dot_p.x
    # 求分母的逆元
    inverse_value = get_inverse(denominator_k, curve.p)
    k = get_remainder(molecule_k * inverse_value, curve.p)
    """
        x3≡k^2-x1-x2(mod p)
        y3≡k(x1-x3)-y1(mod p)
    """
    dot_r = EccDot()
    dot_r.x = (k * k - dot_p.x - dot_q.x) % curve.p
    dot_r.y = (k * (dot_p.x - dot_r.x) - dot_p.y) % curve.p
    return dot_r


# 计算n dot函数
def calculate_np(n, dot):
    """
    求n倍的dot

    Args:
        n (int): 整数，int
        dot (EccDot): 待求倍数的点，EccDot

    Returns:dot的n倍点，EccDot

    """
    dot_r = EccDot()
    p_value = EccDot()
    num_multiple = n

    p_value.x = dot.x
    p_value.y = dot.y
    while num_multiple != 0:
        if (num_multiple & 0x01):
            dot_r.x = p_value.x
            dot_r.y = p_value.y
            break
        p_value = add_p_q(p_value, p_value)
        num_multiple = num_multiple >> 1
        pass

    while num_multiple != 0:
        num_multiple = num_multiple >> 1
        p_value = add_p_q(p_value, p_value)
        if (num_multiple & 0x01):
            dot_r = add_p_q(p_value, dot_r)
    return dot_r
    pass


def generate_keypair():
    """
    生成一对私钥和公钥

    Returns (int EccDot):key_private是私钥，key_public是公钥

    """
    import random
    key_private = random.randint(1000000, curve.p)
    key_public = calculate_np(key_private, curve.G)
    return key_private, key_public
    pass


def get_point_negative(dot):
    """
    求dot 点的负元

    Args:
        dot (EccDot): 需要求负元的点，EccDot

    Returns (EccDot):返回point的负元

    """
    result = EccDot()
    result.x = dot.x
    result.y = (-dot.y) % curve.p
    return result
    pass


def encrypt(dot_message, key_public_encrypt):
    """
    使用公钥key_public_encrypt对消息dot_message进行加密

    Args:
        dot_message (ECCDot): 待加密的明文消息，ECCDot
        key_public_encrypt (ECCDot): 用来加密的公钥，ECCDot

    Returns:加密后的密文，ECCDot

    """
    import random
    key_private_k = random.randint(1000000, curve.p)
    c2 = calculate_np(key_private_k, curve.G)
    key_public_k = calculate_np(key_private_k, key_public_encrypt)

    dot_ciphertext = CipherText()
    c1 = add_p_q(dot_message, key_public_k)
    dot_ciphertext.setc1(c1)
    dot_ciphertext.setc2(c2)
    return dot_ciphertext


def decrypt(key_private_decrypt, dot_ciphertext):
    """
    使用私钥key_private解密公钥加密的消息ciphertext

    Args:
        key_private_decrypt (int): 用来解密的ECC私钥
        dot_ciphertext (CipherText): 待解密的ECC加密数据

    Returns (EccDot):解密后的EccDot类

    """
    kc2 = calculate_np(key_private_decrypt, dot_ciphertext.c2)
    kc2_negative = get_point_negative(kc2)
    message_dot = add_p_q(dot_ciphertext.c1, kc2_negative)
    return message_dot


def hash_message(message):
    """
    目前使用SHA521对message进行hash运算

    Args:
        message (str): 待hash的消息

    Returns (int):消息的hash值

    """
    import hashlib
    """Returns the truncated SHA521 hash of the message."""
    message_hash = hashlib.sha512(message.encode("utf-8")).digest()
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    z = e >> (e.bit_length() - curve.n.bit_length())
    return z
    pass


def sign_ecdsa(key_private_sign, message):
    """
    ECC椭圆曲线 ECDSA签名，使用SHA512

    Args:
        key_private_sign (int): 用来签名的私钥
        message (str): 待签名的信息

    Returns (Signature):返回签名后的Signature()类

    """
    import random
    message_sha512 = hash_message(message)
    key_private_random = random.randint(1, curve.n - 1)
    key_public_random = calculate_np(key_private_random, curve.G)
    key_private_random_inverse = get_inverse(key_private_random, curve.n)

    signature = Signature()
    signature.R = key_public_random.x % curve.n
    signature.S = ((message_sha512 + key_private_sign * signature.R % curve.n) * key_private_random_inverse) % curve.n

    return signature
    pass


def verify_sign_ecdsa(signature, message, key_public_verify):
    """
    使用公钥key_public 验证私钥签名后的message 消息signature

    Args:
        signature (Signature): ECC签名结构类
        message (str): 被签名的消息
        key_public_verify (EccDot): 用来验证签名的公钥

    Returns (bool):验签是否成功：Ture 或 False

    """
    message_sha512 = hash_message(message)
    s_inverse = get_inverse(signature.S, curve.n)

    dot1 = calculate_np(s_inverse * message_sha512 % curve.n, curve.G)
    dot2 = calculate_np(s_inverse * signature.R % curve.n, key_public_verify)
    dot3 = add_p_q(dot1, dot2)

    if (dot3.x % curve.n == signature.R % curve.n):
        return True
    return False
    pass


if __name__ == '__main__':
    # pri = 0x6313d2d113f91a2fafc330d13b5acb167dde21aacf131dfc109d60e938e372f6
    # dot_public = calculate_np(pri, curve.G)

    for i in range(1, 1000):
        print(i)
        key_private, key_public = generate_keypair()
        print('私钥：%#x' % key_private)
        print('公钥x：%#x' % key_public.get_x())
        print('公钥y：%#x' % key_public.get_y())

        ciphertext = encrypt(key_public, key_public)
        plaintext = decrypt(key_private, ciphertext)

        print("encrypt and decrypt:" + str(plaintext.x == key_public.x))

        s = "ecc"
        sig = sign_ecdsa(key_private, s)
        print("sign and verify:" + str(verify_sign_ecdsa(sig, s, key_public)))
        print("===============================================================")

    pass
