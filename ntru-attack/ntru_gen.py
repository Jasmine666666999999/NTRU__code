from numpy import array, zeros, identity, block
from scipy.linalg import circulant
from numpy.random import shuffle
from numpy import random
import numpy as np

def egcd(a, b):
    """
    扩展欧几里得算法。返回 (g, x, y)，使得 ax + by = g = gcd(a, b)。
    """
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    """
    计算模逆元。返回 x，使得 (a * x) % m == 1。
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise ZeroDivisionError("模逆元不存在")
    return x % m

def modinvMat(M, q):
    """
    计算矩阵在模 q 下的逆。
    使用高斯-若尔当消元法。
    """
    n, m = M.shape
    assert m == n, "矩阵必须是方阵"

    # 预计算模 q 下的乘法逆元
    invs = [None] * q
    for i in range(1, q):
        try:
            invs[i] = modinv(i, q)
        except ZeroDivisionError:
            pass

    # 构建增广矩阵 [M | I]
    R = block([[M, identity(n, dtype="long")]])
    
    # 高斯-若尔当消元过程
    for i in range(n):
        # 寻找主元
        pivot_row = -1
        for j in range(i, n):
            if invs[R[j, i]] is not None:
                pivot_row = j
                break
        
        if pivot_row == -1:
            raise ZeroDivisionError("矩阵在模 q 下奇异，不可逆")

        # 将主元行交换到第 i 行
        R[[i, pivot_row]] = R[[pivot_row, i]]
        
        # 将主元归一化为 1
        inv_val = invs[R[i, i]]
        R[i] = (R[i] * inv_val) % q
        
        # 消去当前列的其他非零元素
        for j in range(n):
            if i == j:
                continue
            R[j] = (R[j] - R[i] * R[j, i]) % q

    # 提取逆矩阵部分
    Minv = R[:, n:]
    return Minv

def DiscreteGaussian(shape, sigmasq):
    """
    从离散高斯分布中采样。
    """
    sz = int(np.ceil(10 * np.sqrt(sigmasq)))
    interval = range(-sz, sz + 1)
    p = [np.exp(-x * x / (2 * sigmasq)) for x in interval]
    p_sum = np.sum(p)
    if p_sum == 0:
        # 如果概率和为零（例如 sigmasq 极小），则返回中心值
        return np.full(shape, 0)
    p /= p_sum
    return np.random.choice(interval, shape, p=p)


class NTRUEncrypt_Matrix:
    """
    基于通用矩阵的 NTRU 密钥生成。
    私钥 F 和 G 是从离散高斯分布中采样的矩阵。
    """
    def __init__(self, n, q, sigmasq):
        self.n = n
        self.q = q
        self.sigmasq = sigmasq

    def gen_keys(self):
        """生成公钥 H 和私钥 F, G。"""
        while True:
            F = DiscreteGaussian((self.n, self.n), self.sigmasq)
            try:
                Finv = modinvMat(F, self.q)
                break
            except ZeroDivisionError:
                continue
        G = DiscreteGaussian((self.n, self.n), self.sigmasq)
        H = Finv.dot(G) % self.q
        return H, F, G


class NTRUEncrypt_Circulant:
    """
    基于循环矩阵的 NTRU 密钥生成。
    私钥 f 和 g 是从离散高斯分布中采样的向量，然后扩展成循环矩阵。
    """
    def __init__(self, n, q, sigmasq):
        self.n = n
        self.q = q
        self.sigmasq = sigmasq

    def gen_keys(self):
        """生成公钥 H 和私钥 F, G（均为循环矩阵）。"""
        while True:
            f = DiscreteGaussian(self.n, self.sigmasq)
            F = circulant(f)
            try:
                Finv = modinvMat(F, self.q)
                break
            except ZeroDivisionError:
                continue
        g = DiscreteGaussian(self.n, self.sigmasq)
        G = circulant(g)
        H = Finv.dot(G) % self.q
        return H, F, G


class NTRUEncrypt:
    """
    标准 NTRU 密钥生成。
    私钥 f 和 g 是从三元分布 {-1, 0, 1} 中采样的向量。
    """
    def __init__(self, n, q, Df, Dg):
        self.n = n
        self.q = q
        self.Df = Df
        self.Dg = Dg

    def sample_ternary(self, ones, minus_ones):
        """从三元分布中采样一个向量。"""
        s = [1] * ones + [-1] * minus_ones + [0] * (self.n - ones - minus_ones)
        shuffle(s)
        return s

    def gen_keys(self):
        """生成公钥 H 和私钥 F, G（均为循环矩阵）。"""
        while True:
            f = self.sample_ternary(self.Df, self.Df - 1)
            F = circulant(f)
            try:
                Finv = modinvMat(F, self.q)
                break
            except ZeroDivisionError:
                continue

        g = self.sample_ternary(self.Dg, self.Dg)
        G = circulant(g)
        H = G.dot(Finv) % self.q
        return H, F, G


def build_ntru_lattice(n, q, H):
    """
    根据公钥 H 构建 NTRU 格的基矩阵。
    """
    I = identity(n, dtype="long")
    O = zeros((n, n), dtype="long")
    # 构建 2n x 2n 的格基
    # [[ q*I,  O ],
    #  [  H ,  I ]]
    return block([[q * I, O], [H, I]])


def gen_ntru_instance_matrix(n, q, sigmasq, seed=None):
    """
    生成一个基于通用矩阵的 NTRU 实例，返回格基 B 和私钥 F, G。
    """
    if seed is not None:
        random.seed(np.uint32(seed))
    ntru = NTRUEncrypt_Matrix(n, q, sigmasq)
    H, F, G = ntru.gen_keys()
    B = build_ntru_lattice(n, q, H)
    return B, F, G

def gen_ntru_instance_circulant(n, q, sigmasq, seed=None):
    """
    生成一个基于循环矩阵的 NTRU 实例，返回格基 B 和私钥 F, G。
    """
    if seed is not None:
        random.seed(np.uint32(seed))
    ntru = NTRUEncrypt_Circulant(n, q, sigmasq)
    H, F, G = ntru.gen_keys()
    B = build_ntru_lattice(n, q, H)
    return B, F, G

def gen_ntru_instance(n, q, Df=None, Dg=None, seed=None):
    """
    生成一个标准的 NTRU 实例，返回格基 B 和私钥 f, g 的首行。
    """
    if seed is not None:
        random.seed(np.uint32(seed))
        
    if Df is None: Df = n // 3
    if Dg is None: Dg = n // 3

    ntru = NTRUEncrypt(n, q, Dg, Df)
    H, F, G = ntru.gen_keys()
    # 注意这里 H 被转置，以匹配某些攻击场景的格构造
    B = build_ntru_lattice(n, q, H.transpose())
    return B, [F[0], G[0]]
