import numpy as np
from enc import NTRUencrypt
from dec import NTRUdecrypt
from utils import *
from options import get_args
import sys
from os.path import exists
import os

# 主执行函数
if __name__ == "__main__":
    
    # 解析命令行参数
    args = get_args()

    # 如果没有提供命令行参数，则运行一个默认的演示流程
    if len(sys.argv) == 1:
        print("未提供参数，运行默认演示...")

        # 1. 设置参数并生成密钥
        key_name = "demo_key"
        print(f"\n1. 使用默认高安全参数(N=167, p=3, q=128)生成密钥。")
        key_gen = NTRUdecrypt()
        key_gen.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)
        key_gen.genPubPriv(key_name)
        print(f"   公钥已保存至 '{key_name}.pub'")
        print(f"   私钥已保存至 '{key_name}.priv'")

        # 2. 加密示例消息
        message = "This is a test of the NTRU implementation."
        print(f"\n2. 明文: '{message}'")
        encryptor = NTRUencrypt()
        encryptor.readPub(f"{key_name}.pub")
        encryptor.encryptString(message)
        encrypted_message = encryptor.Me
        print(f"   密文: {encrypted_message}")

        # 3. 解密消息
        print("\n3. 解密...")
        decryptor = NTRUdecrypt()
        decryptor.readPriv(f"{key_name}.priv")
        decryptor.decryptString(encrypted_message)
        decrypted_message = decryptor.M
        print(f"   解密消息: '{decrypted_message}'")

        # 4. 验证结果
        print("\n4. 验证")
        if message == decrypted_message:
            print("   成功: 解密消息与原始消息匹配。")
        else:
            print("   失败: 解密消息与原始消息不匹配。")
        
        # 清理生成的密钥文件
        try:
            os.remove(f"{key_name}.pub")
            os.remove(f"{key_name}.priv")
            print("\n已清理生成的密钥文件。")
        except OSError as e:
            print(f"清理文件时出错: {e}")

    # --- 处理命令行参数 ---

    # 处理密钥生成请求
    elif (args.Gen):
        N1 = NTRUdecrypt()
        if (args.moderate_sec):
            N1.setNpq(N=107,p=3,q=64,df=15,dg=12,d=5)
        elif (args.highest_sec):
            N1.setNpq(N=503,p=3,q=256,df=216,dg=72,d=55)
        else:
            N1.setNpq(N=args.N, p=args.p, q=args.q, df=args.df, dg=args.dg, d=args.d)
            
        print(f"使用参数 N={N1.N}, p={N1.p}, q={N1.q} 生成密钥...")
        N1.genPubPriv(args.key_name)
        print(f"公钥已保存至 '{args.key_name}.pub'")
        print(f"私钥已保存至 '{args.key_name}.priv'")

    # 处理加密请求 (字符串或文件)
    elif (args.Enc_string or args.Enc_file):
        if not exists(args.key_name+".pub"):
            sys.exit(f"错误: 未找到公钥 '{args.key_name}.pub'。")
        if args.Enc_string and args.Enc_file:
            sys.exit("错误: 提供了多个加密输入源。")
        if not args.out_file and not args.out_in_term:
            sys.exit("错误: 必须指定至少一种输出方式。")
        
        E = NTRUencrypt()
        E.readPub(args.key_name+".pub")
        
        if args.Enc_string:
            to_encrypt = args.Enc_string
        elif args.Enc_file:
            if not exists(args.Enc_file):
                sys.exit(f"错误: 未找到输入文件 '{args.Enc_file}'。")
            with open(args.Enc_file,"r") as f:
                to_encrypt = "".join(f.readlines())
        
        E.encryptString(to_encrypt)
        
        if args.out_in_term:
            print(E.Me)
        if args.out_file:
            with open(args.out_file,"w") as f:
                f.write(E.Me)

    # 处理解密请求 (字符串或文件)
    elif (args.Dec_string or args.Dec_file):
        if not exists(args.key_name+".priv"):
            sys.exit(f"错误: 未找到私钥 '{args.key_name}.priv'。")
        if args.Dec_string and args.Dec_file:
            sys.exit("错误: 提供了多个解密输入源。")
        if not args.out_file and not args.out_in_term:
            sys.exit("错误: 必须指定至少一种输出方式。")

        D = NTRUdecrypt()
        D.readPriv(args.key_name+".priv")

        if args.Dec_string:
            to_decrypt = args.Dec_string
        elif args.Dec_file:
            if not exists(args.Dec_file):
                sys.exit(f"错误: 未找到输入文件 '{args.Dec_file}'。")
            with open(args.Dec_file,"r") as f:
                to_decrypt = "".join(f.readlines())
        
        D.decryptString(to_decrypt)
        
        if args.out_in_term:
            print(D.M)
        if args.out_file:
            with open(args.out_file,"w") as f:
                f.write(D.M)
