import argparse
from argparse import RawTextHelpFormatter

# 定义并解析所有命令行参数
def get_args():
    parser = argparse.ArgumentParser(prog="NTRU Encrypt/Decrypt",
                                     formatter_class=RawTextHelpFormatter)
    
    # --- 通用参数 ---
    parser.add_argument("-k","--key-name",default="key",type=str,
                        help="公钥和私钥的文件名 (key_name.pub 和 key_name.priv)。")
    parser.add_argument("-O","--out_file",type=str,
                        help="用于加密/解密数据/字符串的输出文件。")
    parser.add_argument("-T","--out_in_term",action="store_true",
                        help="将加密/解密的数据/字符串输出到终端。")

    # --- 密钥生成参数 ---
    parser.add_argument("-G","--Gen",action="store_true",
                        help="生成公钥和私钥文件。\n默认密钥参数为[1]中的高安全级别参数。")
    parser.add_argument("-M","--moderate_sec",action="store_true",
                        help="与-G标志一同使用，生成[1]中的中等安全级别密钥 (N=107, p=3, q=64)。")
    parser.add_argument("-H","--high-sec",action="store_true",
                        help="与-G标志一同使用，生成[1]中的高安全级别密钥 (N=167, p=3, q=128)。")
    parser.add_argument("-HH","--highest-sec",action="store_true",
                        help="与-G标志一同使用，生成[1]中的最高安全级别密钥 (N=503, p=3, q=256)。")
    
    # --- 自定义NTRU参数 ---
    parser.add_argument("-N","--N",default=167,type=int,
                        help="多项式环的阶，默认为167。")
    parser.add_argument("-p","--p",default=3,type=int,
                        help="较小的逆多项式模数，默认为3。")
    parser.add_argument("-q","--q",default=128,type=int,
                        help="较大的逆多-y项式模数，默认为128。")
    parser.add_argument("-df","--df",default=61,type=int,
                        help="多项式f有df个1和df-1个-1，默认为61。")
    parser.add_argument("-dg","--dg",default=20,type=int,
                        help="多项式g有dg个1和-1，默认为20。")
    parser.add_argument("-d","--d",default=18,type=int,
                        help="随机致盲多项式有d个1和-1，默认为18。")

    # --- 加密参数 ---
    parser.add_argument("-eS","--Enc_string",type=str,
                        help="加密作为输入的字符串。\n注意: 字符串必须用引号括起来，例如 \"a string\"。\n需要一个已知的公钥。")
    parser.add_argument("-eF","--Enc_file",type=str,
                        help="加密此输入文件中的字符串。\n需要一个已知的公钥。")

    # --- 解密参数 ---
    parser.add_argument("-dS","--Dec_string",type=str,
                        help="解密作为输入的字符串。\n注意: 字符串必须用引号括起来，例如 \"a string\"。\n需要一个已知的私钥。")
    parser.add_argument("-dF","--Dec_file",type=str,
                        help="解密此输入文件中的字符串。\n需要一个已知的私钥。")

    return parser.parse_args()
