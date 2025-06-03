from __future__ import absolute_import
import copy
from collections import OrderedDict
from math import sqrt, log
import six
from six.moves import range

import numpy as np
from numpy import array, zeros, block, transpose
from numpy.linalg import slogdet
from scipy.linalg import circulant
from scipy.stats import linregress

from fpylll import IntegerMatrix, BKZ, GSO
from fpylll.fplll.lll import LLLReduction
from bkz_cb import BKZReduction
from cli import parse_args, run_all, pretty_dict
from ntru_gen import gen_ntru_instance_matrix, gen_ntru_instance_circulant

def is_prime(x):
    """判断一个数是否为质数。"""
    return all(x % i for i in range(2, int(sqrt(x)) + 1))

def next_prime(x):
    """找到大于 x 的下一个质数。"""
    return min([a for a in range(x + 1, 2 * x) if is_prime(a)])

def sqnorm(a):
    """计算向量的欧几里得范数平方。"""
    return sum([x**2 for x in a])

class DenseSubLatticeFound(Exception):
    """
    自定义异常，在攻击成功（找到稠密子格中的向量）时抛出。
    用于中断 BKZ 算法并传递攻击结果。
    """
    def __init__(self, call_stack, lf, vcan, vgs, vloc, gso):
        self.call_stack = call_stack # BKZ 调用栈
        self.lf = lf                 # 长度因子
        self.vcan = vcan             # 规范基下的向量
        self.vgs = vgs               # 格拉姆-施密特正交化后的向量分量范数平方
        self.vloc = vloc             # 局部基下的向量坐标
        self.gso = gso               # 格拉姆-施密特正交化长度的对数

def ntru_kernel(job_data):
    """
    NTRU 攻击的核心实验函数。
    针对单一一组参数运行一次完整的攻击流程。
    """
    # 从任务数据中解包参数和种子
    params, seed = job_data
    params = copy.copy(params)

    # 获取 NTRU 参数
    n = params["n"]
    q = params["q"]
    float_type = params.get("float_type", "double")
    circ = params.get("circulant", True)
    tours = params.get("tours", 8)
    sigmasq = params.get("sigmasq", 0.667)

    # 根据参数生成 NTRU 实例（格基 B 和私钥 F, G）
    if circ:
        B, F, G = gen_ntru_instance_circulant(n, q, sigmasq, seed)
    else:
        B, F, G = gen_ntru_instance_matrix(n, q, sigmasq, seed)

    # 设置 fpylll 格对象
    A = IntegerMatrix.from_matrix([[int(x) for x in v] for v in B])
    M = GSO.Mat(A, float_type=float_type)
    
    # 首先进行 LLL 约化
    lll = LLLReduction(M)
    lll()
    
    # 初始化自定义的 BKZ 对象
    bkz = BKZReduction(M)
    M.update_gso()

    # 计算私钥范数作为参考
    sk_norms = [sqnorm(F[i]) + sqnorm(G[i]) for i in range(n)]
    sk_norm_min = min(sk_norms)
    sk_norm_max = max(sk_norms)
    
    # 构建用于验证向量是否属于目标子格的变换矩阵 Tfg
    if circ:
        Tfg = block([[F], [-G]])
    else:
        Tfg = block([[F], [-np.linalg.inv(F).dot(G).dot(F)]])
    
    # 计算目标稠密子格的体积对数
    DS_vol = slogdet(transpose(Tfg).dot(Tfg))[1] / 2.

    def insert_callback(call_stack, solution):
        """
        BKZ 算法的回调函数，在找到短向量时被调用。
        用于检测找到的向量是否为我们寻找的私钥相关向量。
        """
        kappa, b = call_stack[-1]
        
        # 将局部基下的解向量转换回规范基
        v = (bkz.M.B[kappa:kappa + b]).multiply_left(solution)
        lift_fix = bkz.M.babai(v, 0, kappa)
        lift_can = (bkz.M.B[0:kappa]).multiply_left(lift_fix)
        v = array(v) - array(lift_can)

        # 检查向量 v 是否属于目标稠密子格 (即 Tfg*v^T 约等于 0)
        x = v.dot(Tfg)
        if any(np.abs(x) > 0.001): return
        
        # 检查向量长度是否在合理范围内
        if sqnorm(v) < sk_norm_min: return
        
        # 计算长度因子并抛出异常，表示攻击成功
        lf = sqnorm(v) / sk_norm_max
        vg = bkz.M.from_canonical(v, start=0, dimension=kappa + b)
        vgs = [vg[i]**2 * bkz.M.r()[i] for i in range(kappa + b)]
        raise DenseSubLatticeFound(call_stack, lf, v, vgs, solution, bkz.M.r())

    # 将回调函数注册到 BKZ 对象
    bkz.insert_callback = insert_callback

    # 逐步增加 BKZ 块大小进行攻击
    for blocksize in list(range(2, n + 1)):
        if tours is None: tours = 8
        
        par = BKZ.Param(blocksize,
                        strategies=BKZ.DEFAULT_STRATEGY,
                        flags=BKZ.BOUNDED_LLL,
                        max_loops=tours)
        try:
            bkz(par)
        except DenseSubLatticeFound as err:
            # 捕获到成功信号，整理并返回统计数据
            kappa, b = err.call_stack[0]
            vsz = np.sum(np.abs(err.vloc))
            logr = [log(x) / 2. for x in err.gso]
            d = len(err.gso)

            # 计算 GSO 向量长度剖面的斜率
            slope_part = min(30, n)
            l, r = n - slope_part, n + slope_part
            slope = -linregress(range(l, r), logr[l:r]).slope if r > l and r <= d and l >= 0 else float('nan')
            
            byLLL = vsz < 1.5
            sq_proj_sz = np.sum(err.vgs[kappa:kappa + b]) / np.sum(err.vgs[:kappa + b])
            
            # 判断是稠密子格发现（DSD）还是密钥恢复（SKR）
            if err.lf > 1.:
                stats = {"DSD": True, "DSD_lf": err.lf, "kappa": kappa, "beta": blocksize, "DS_vol": DS_vol, "foundbyLLL": byLLL, "slope": slope, "sqproj_rel": sq_proj_sz}
            else:
                stats = {"DSD": False, "DSD_lf": 1., "kappa": kappa, "beta": blocksize, "DS_vol": DS_vol, "foundbyLLL": byLLL, "slope": slope, "sqproj_rel": sq_proj_sz}
            
            return stats

    return None

def ntru():
    """
    运行 NTRU 攻击实验的主程序。
    """
    description = ntru.__doc__

    # 解析命令行参数，设置默认参数
    args, all_params = parse_args(description,
                                  n=127,
                                  q=739,
                                  float_type="long double",
                                  circulant=True,
                                  tours=8,
                                  sigmasq=0.667)

    # 运行所有参数组合的实验
    stats = run_all(ntru_kernel, list(all_params.values()),
                    trials=args.trials,
                    workers=args.workers)

    # 汇总并打印平均统计数据
    if stats:
        print("\n\n 平均数据\n\n ")
        for param_key_str, results_list in six.iteritems(stats):
            avg = OrderedDict()
            valid_results_count = sum(1 for r in results_list if r is not None)
            if not valid_results_count: continue

            # 累加所有有效试验的结果
            first_valid_result = next(r for r in results_list if r is not None)
            for k in first_valid_result.keys():
                avg[k] = sum(r.get(k, 0.0) for r in results_list if r is not None)
            
            # 计算平均值
            for k in avg:
                avg[k] /= valid_results_count

            print(pretty_dict(param_key_str))
            keys = first_valid_result.keys()
            print(", ".join(["%14s" % k for k in keys]))
            print(", ".join(["%14.4f" % avg.get(k, float('nan')) for k in keys]))
            print()

    # 如果指定，则打印所有试验的完整原始数据
    if args.full_data and stats:
        print("\n\n 完整数据 (CSV格式)\n\n ")
        for param_key_str, results_list in six.iteritems(stats):
            if not results_list: continue

            print(pretty_dict(param_key_str))
            first_valid_result = next((r for r in results_list if r is not None), None)
            if not first_valid_result: continue
            
            keys = first_valid_result.keys()
            print(", ".join(["%14s" % k for k in keys]))
            for res in results_list:
                if res is None:
                    print(",".join(["%14s" % "N/A"] * len(keys)))
                else:
                    print(", ".join(["%14.4f" % res.get(k, float('nan')) for k in keys]))

if __name__ == "__main__":
    # 脚本入口
    ntru()
