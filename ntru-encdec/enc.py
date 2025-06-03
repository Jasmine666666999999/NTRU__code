import numpy as np
import sys
from sympy import Poly, symbols
from utils import *

# NTRU加密类
class NTRUencrypt:
    # 该类用于使用已知的公钥来加密数据。
    
    # 初始化NTRU参数
    def __init__(self, N=503, p=3, q=256, d=18):
        # --- 公共参数 ---
        self.N = N  # 多项式环的阶
        self.p = p  # 模数p
        self.q = q  # 模数q
        self.dr = d # 随机多项式r中1的数量
        
        # --- 密钥与消息多项式 ---
        self.h = np.zeros((self.N,), dtype=int) # 公钥
        self.r = np.zeros((self.N,), dtype=int) # 随机致盲多项式
        self.m = np.zeros((self.N,), dtype=int) # 待加密消息
        self.e = np.zeros((self.N,), dtype=int) # 加密后的消息

        # --- 环的理想 I = X^N - 1 ---
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

        # --- 状态标志 ---
        self.readKey = False # 是否已读取公钥文件
        
        # --- 加密结果 ---
        self.Me = None # 字符串形式的加密消息

        # --- 初始化操作 ---
        self.genr() # 生成一个初始的随机多项式

    # 从文件读取公钥
    def readPub(self,filename="key.pub"):
        with open(filename,"r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            self.h  = np.array(f.readline().split(" ")[3:-1],dtype=int)
        
        # 根据读取的N重新初始化相关数组
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1
        self.genr()
        self.readKey = True

    # 生成随机致盲多项式r
    def genr(self):
        self.r = genRand10(self.N,self.dr,self.dr)
        
    # 设置待加密的消息多项式M
    def setM(self,M):
        if self.readKey==False:
            sys.exit("错误: 在设置消息前未读取公钥")
        if len(M)>self.N:
            sys.exit("错误: 消息长度超过多项式环的阶")
        for i in range(len(M)):
            if M[i]<-self.p/2 or M[i]>self.p/2:
                sys.exit("错误: 消息元素的范围必须在[-p/2, p/2]之间")
        
        # 将消息填充至长度N
        self.m = padArr(M,self.N)

    # 加密核心操作
    def encrypt(self,m=None):
        if self.readKey == False:
            sys.exit("错误: 未读取公钥文件，无法加密")
        
        if m is not None:
            if len(m)>self.N:
                sys.exit("\n\n错误: 消息多项式的阶数大于等于N")
            self.m = m
        
        x = symbols('x')
        # 加密公式: e = r * h + m (mod q)
        rh = Poly(self.r,x) * Poly(self.h,x)
        rh_mod_q = rh.trunc(self.q)
        e_poly = (rh_mod_q + Poly(self.m,x)) % Poly(self.I,x)
        e_poly_mod_q = e_poly.trunc(self.q)

        self.e = padArr(np.array(e_poly_mod_q.all_coeffs(), dtype=int), self.N)

    # 加密字符串
    def encryptString(self,M):
        if self.readKey == False:
            sys.exit("错误: 未读取公钥文件，无法加密")
        
        # 将字符串转换为二进制数组，并填充使其长度为N的倍数
        bM = str2bit(M)
        bM = padArr(bM,len(bM)-np.mod(len(bM),self.N)+self.N)
        
        self.Me = ""

        # 对每个数据块进行加密
        for E in range(len(bM)//self.N):
            self.genr()                           # 为每个块生成新的随机多项式
            self.setM(bM[E*self.N:(E+1)*self.N])   # 设置当前块为待加密消息
            self.encrypt()                        # 加密
            self.Me += arr2str(self.e) + " "      # 拼接加密结果
