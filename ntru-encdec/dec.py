import numpy as np
from math import log, gcd
import sys
from sympy import Poly, symbols
from utils import *

# NTRU解密类
class NTRUdecrypt:
    # 该类用于实现NTRU解密，同时也能生成用于解密的私钥和用于加密的公钥。
    
    # 初始化NTRU参数
    def __init__(self, N=503, p=3, q=256, df=61, dg=20, d=18):
        # --- 公共参数 ---
        self.N = N  # 多项式环的阶
        self.p = p  # 模数p
        self.q = q  # 模数q

        # --- 私有参数 ---
        self.df = df  # 多项式f中1的数量
        self.dg = dg  # 多项式g中1的数量
        self.dr = d   # 随机多项式r中1的数量（加密时使用）
        
        # --- 密钥多项式 ---
        self.f  = np.zeros((self.N,), dtype=int)  # 私有多项式 f
        self.fp = np.zeros((self.N,), dtype=int)  # f 模 p 的逆
        self.fq = np.zeros((self.N,), dtype=int)  # f 模 q 的逆
        self.g  = np.zeros((self.N,), dtype=int)  # 私有多项式 g
        self.h  = np.zeros((self.N,), dtype=int)  # 公钥 h = p * fq * g (mod q)

        # --- 环的理想 I = X^N - 1 ---
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

        # --- 解密后的消息 ---
        self.M = None

    # 设置并验证N, p, q等参数
    def setNpq(self,N=None,p=None,q=None,df=None,dg=None,d=None):
        # 检查N是否为素数、q是否大于p、p和q是否互质
        if N is not None:
            if (not checkPrime(N)):
                sys.exit("\n\n错误: 输入的N值不是素数\n\n")
            else:
                if df is None:
                    if 2*self.df>N: sys.exit(f"\n\n错误: 输入的N相对于默认的df({self.df})太小\n\n")
                if dg is None:
                    if 2*self.dg>N: sys.exit(f"\n\n错误: 输入的N相对于默认的dg({self.dg})太小\n\n")
                if d is None:
                    if 2*self.dr>N: sys.exit(f"\n\n错误: 输入的N相对于默认的dr({self.dr})太小\n\n")
                
                self.N  = N
                self.f  = np.zeros((self.N,), dtype=int)
                self.fp = np.zeros((self.N,), dtype=int)
                self.fq = np.zeros((self.N,), dtype=int)
                self.g  = np.zeros((self.N,), dtype=int)
                self.h  = np.zeros((self.N,), dtype=int)
                self.I         = np.zeros((self.N+1,), dtype=int)
                self.I[self.N] = -1
                self.I[0]      = 1

        if (p is not None) and (q is not None):
            if ((8*p)>q):
                sys.exit("\n\n错误: 需要满足 8*p <= q\n\n")
            if (gcd(p,q)!=1):
                sys.exit("\n\n错误: 输入的p和q不互质\n\n")
            self.p = p
            self.q = q
        elif (p is None and q is not None) or (p is not None and q is None):
            sys.exit("\n\n错误: p和q必须同时设置")

        if df is not None:
            if 2*df>self.N: sys.exit("\n\n错误: 输入的df不满足2*df <= N\n\n")
            self.df = df

        if dg is not None:
            if 2*dg>self.N: sys.exit("\n\n错误: 输入的dg不满足2*dg <= N\n\n")
            self.dg = dg
                
        if d is not None:
            if 2*d>self.N: sys.exit("\n\n错误: 输入的dr不满足2*d <= N\n\n")
            self.dr = d
                    
    # 计算私有多项式f模p和模q的逆
    def invf(self):
        fp_tmp = poly_inv(self.f,self.I,self.p)
        fq_tmp = poly_inv(self.f,self.I,self.q)
        if len(fp_tmp)>0 and len(fq_tmp)>0:
            self.fp = np.array(fp_tmp)
            self.fq = np.array(fq_tmp)
            if len(self.fp)<self.N:
                self.fp = np.concatenate([np.zeros(self.N-len(self.fp),dtype=int),self.fp])
            if len(self.fq)<self.N:
                self.fq = np.concatenate([np.zeros(self.N-len(self.fq),dtype=int),self.fq])            
            return True
        else:
            return False

    # 随机生成私有多项式f和g
    def genfg(self):
        # 循环尝试生成一个可逆的f
        maxTries = 100
        self.g = genRand10(self.N,self.dg,self.dg)
        for i in range(maxTries):
            self.f = genRand10(self.N,self.df,self.df-1)
            if self.invf():
                break
            elif i==maxTries-1:
                sys.exit("无法生成f所需的可逆多项式")

    # 根据私钥生成公钥h
    def genh(self):
        x = symbols('x')
        self.h = Poly((Poly(self.p*self.fq,x).trunc(self.q)*Poly(self.g,x)).trunc(self.q)\
                      %Poly(self.I,x)).all_coeffs()

    # 将公钥写入文件
    def writePub(self,filename="key"):
        pubHead = f"p ::: {self.p}\nq ::: {self.q}\nN ::: {self.N}\nd ::: {self.dr}\nh :::"
        np.savetxt(filename+".pub", self.h, newline=" ", header=pubHead, fmt="%s")

    # 从文件读取公钥
    def readPub(self,filename="key.pub"):
        with open(filename,"r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            self.h  = np.array(f.readline().split(" ")[3:-1],dtype=int)
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

    # 将私钥写入文件
    def writePriv(self,filename="key"):
        privHead = f"p ::: {self.p}\nq ::: {self.q}\nN ::: {self.N}\ndf ::: {self.df}\n" \
                   f"dg ::: {self.dg}\nd ::: {self.dr}\nf/fp/fq/g :::"
        np.savetxt(filename+".priv", (self.f,self.fp,self.fq,self.g), header=privHead, newline="\n", fmt="%s")

    # 从文件读取私钥
    def readPriv(self,filename="key.priv"):
        with open(filename,"r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.df = int(f.readline().split(" ")[-1])
            self.dg = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            f.readline()
            self.f  = np.array(f.readline().split(" "),dtype=int)
            self.fp = np.array(f.readline().split(" "),dtype=int)
            self.fq = np.array(f.readline().split(" "),dtype=int)
            self.g  = np.array(f.readline().split(" "),dtype=int)
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1
    
    # 生成公私钥对并保存到文件
    def genPubPriv(self,keyfileName="key"):
        self.genfg()
        self.genh()
        self.writePub(keyfileName)
        self.writePriv(keyfileName)

    # 解密核心操作
    def decrypt(self,e):
        if len(e)>self.N:
            sys.exit("密文多项式的阶数不能超过N")
        x = symbols('x')
        # a = f * e (mod q)
        a = ((Poly(self.f,x)*Poly(e,x))%Poly(self.I,x)).trunc(self.q)
        # b = a (mod p)
        b = a.trunc(self.p)
        # c = fp * b (mod p)
        c = ((Poly(self.fp,x)*b)%Poly(self.I,x)).trunc(self.p)
        return np.array(c.all_coeffs(),dtype=int)

    # 解密字符串
    def decryptString(self,E):
        # 将输入字符串转换为numpy数组
        Me = np.fromstring(E, dtype=int, sep=' ')
        if np.mod(len(Me),self.N)!=0:
            sys.exit("\n\n错误: 输入的待解密字符串长度不是N的整数倍\n\n")

        # 对每个数据块进行解密并拼接
        Marr = np.array([],dtype=int)
        for D in range(len(Me)//self.N):
            decrypted_block = self.decrypt(Me[D*self.N:(D+1)*self.N])
            padded_block = padArr(decrypted_block, self.N)
            Marr = np.concatenate((Marr, padded_block))

        # 将二进制数组转换为字符串
        self.M = bit2str(Marr)
