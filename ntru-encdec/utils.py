import numpy as np
from math import log, gcd
import random
import sys
from sympy import Poly, symbols, GF, invert

np.set_printoptions(threshold=sys.maxsize)

# 检查一个整数是否为素数
def checkPrime(P):
    if (P<=1): return False
    if (P==2 or P==3): return True
    for i in range(4,P//2):
        if (P%i==0): return False
    return True

# 计算多项式在伽罗瓦域(GF)中的逆
def poly_inv(poly_in,poly_I,poly_mod):
    x = symbols('x')
    Npoly_I = len(Poly(poly_I, x).all_coeffs())

    inv = None
    if checkPrime(poly_mod):
        # 如果模数是素数，直接在GF(p)中计算
        domain = GF(poly_mod, symmetric=False)
        Ppoly_I_mod = Poly(poly_I, x, domain=domain)
        try:
            inv = invert(Poly(poly_in, x).as_expr(), Ppoly_I_mod.as_expr(), domain=domain)
        except:
            return np.array([])
    elif log(poly_mod, 2).is_integer():
        # 如果模数是2的幂，使用Hensel's Lemma进行提升
        Ppoly_I_int = Poly(poly_I, x)
        try:
            # 步骤1: 计算模2的逆
            inv = invert(Poly(poly_in,x).as_expr(),Ppoly_I_int.as_expr(),domain=GF(2,symmetric=False))
            ex = int(log(poly_mod,2))
            # 步骤2: 将解从模2提升到模2^k
            for a in range(1,ex):
                inv = ((2*Poly(inv,x)-Poly(poly_in,x)*Poly(inv,x)**2)%Ppoly_I_int).trunc(poly_mod)
        except:
            return np.array([])
    else:
        return np.array([])

    # 验证计算出的逆是否正确
    p_inv = Poly(inv, x)
    p_poly_in = Poly(poly_in, x)
    Ppoly_I_int = Poly(poly_I, x)
    check_res = (p_inv * p_poly_in) % Ppoly_I_int
    check_res_trunc = check_res.trunc(poly_mod)
    tmpCheck = np.array(check_res_trunc.all_coeffs(), dtype=int)
    
    if len(tmpCheck) > 1 or tmpCheck[0] != 1:
        sys.exit("错误: 多项式求逆计算出错")

    return padArr(np.array(p_inv.all_coeffs(), dtype=int), Npoly_I - 1)

# 使用前导零填充数组
def padArr(A_in,A_out_size):
    padding_size = A_out_size - len(A_in)
    if padding_size < 0:
        return A_in
    return np.pad(A_in,(padding_size,0),constant_values=(0))

# 生成一个包含P个1，M个-1和其余为0的随机数组
def genRand10(L,P,M):
    if P+M>L:
        sys.exit("错误: 1和-1的总数不能超过数组长度L。")
    R = np.zeros((L,),dtype=int)
    R[:P] = 1
    R[P:P+M] = -1
    np.random.shuffle(R)
    return R

# 将numpy数组转换为格式化的字符串
def arr2str(ar):
    st = np.array_str(ar)
    st = st.replace("[", "").replace("]", "").replace("\n", "")
    return ' '.join(st.split())

# 将字符串转换为二进制表示的numpy数组
def str2bit(st):
    encoded_str = str(st).encode("utf-8", errors="ignore")
    binary_str = bin(int.from_bytes(encoded_str, "big"))
    return np.array(list(binary_str)[2:], dtype=int)

# 将二进制表示的数组转换为字符串
def bit2str(bi):
    S = arr2str(bi).replace(" ", "")
    
    # 确保位数是8的倍数
    rem = len(S) % 8
    if rem != 0:
        S = '0' * (8 - rem) + S
        
    n = int(S, 2)
    try:
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode("utf-8", "ignore") or ''
    except Exception:
        return ""
