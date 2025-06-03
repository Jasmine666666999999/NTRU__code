# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function
import argparse
import copy
import re
from collections import OrderedDict
from multiprocessing import Pool
from random import randint
from math import sqrt
import six
from six.moves import range

def is_prime(x):
    """
    检查一个数是否为质数。
    """
    return all(x % i for i in range(2, int(sqrt(x)) + 1))

def run_all(f, params_list, trials=1, workers=1, seed=None):
    """
    为多组参数组合并行或串行地运行实验函数。

    :param f: 要执行的实验函数。
    :param params_list: 参数字典的列表，每个字典代表一组实验配置。
    :param trials: 每组参数配置需要重复运行的次数。
    :param workers: 并行执行的进程数。
    :param seed: 随机数种子。
    """
    if seed is None:
        seed = randint(0, 2**31)

    jobs, stats = [], OrderedDict()
    for params_from_list_item in params_list:
        stats[str(params_from_list_item)] = []
        for t in range(trials):
            seed += 1
            current_job_params = copy.deepcopy(params_from_list_item)
            # 任务参数是一个元组 (参数字典, 种子)
            args_for_f = (current_job_params, seed)
            jobs.append(args_for_f)

    # 根据工作进程数选择串行或并行执行
    if workers == 1:
        for job_tuple in jobs:
            res = f(job_tuple)
            stats[str(job_tuple[0])].append(res)
    else:
        pool = Pool(workers)
        results = pool.map(f, jobs)
        pool.close()
        pool.join()
        for i, res in enumerate(results):
            stats[str(jobs[i][0])].append(res)

    return stats

def parse_args(description, **kwds):
    """
    解析命令行参数，支持标准参数和用户自定义的任意参数组合。
    
    能够解析 --n, --q, --trials, --workers 等标准参数，
    还能将未知的参数（如 --beta 10 20 30）解析为多组实验配置。
    支持范围表示法，如 "10~20" 或 "100~200p" (质数范围)。
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # 定义标准、已知的命令行参数
    parser.add_argument('-t', '--trials', type=int, dest="trials", default=1)
    parser.add_argument('-w', '--workers', type=int, dest="workers", default=1)
    parser.add_argument('-f', '--full_data', type=bool, dest="full_data", default=0)
    parser.add_argument('--n', type=int, dest="n", default=None)
    parser.add_argument('--q', type=int, dest="q", default=None)

    args, unknown = parser.parse_known_args()

    # 使用命令行传入的 n 和 q 覆盖默认值
    if args.n is not None:
        kwds['n'] = args.n
    if args.q is not None:
        kwds['q'] = args.q

    all_params = OrderedDict([("", kwds)])
    unknown_args = OrderedDict()
    
    # 解析所有未知的命令行参数，用于生成参数组合
    i = 0
    while i < len(unknown):
        k = unknown[i]
        if not (k.startswith("--") or k.startswith("-")):
            raise ValueError("无法解析命令行参数 '%s'" % k)
        k = re.match("^-+(.*)", k).groups()[0].replace("-", "_")
        unknown_args[k] = []
        i += 1
        
        # 读取参数值，直到遇到下一个参数
        for i in range(i, len(unknown)):
            v = unknown[i]
            if v.startswith("--") or v.startswith("-"):
                i -= 1
                break

            # 尝试解析 "start~endp" 格式的质数范围
            try:
                L = re.match("([0-9]+)~([0-9]+)p", v).groups()
                v_parsed = [x for x in range(int(L[0]), int(L[1])) if is_prime(x)]
                unknown_args[k].extend(v_parsed)
                continue
            except:
                pass
            
            # 尝试解析 "start~end~step" 或 "start~end" 格式的数值范围
            try:
                L = re.match("([0-9]+)~([0-9]+)~?([0-9]+)?", v).groups()
                v_parsed = list(range(int(L[0]), int(L[1]), int(L[2]) if L[2] else 1))
                unknown_args[k].extend(v_parsed)
                continue
            except:
                pass
            
            # 尝试解析为整数或字符串
            try:
                unknown_args[k].append(int(v))
            except:
                unknown_args[k].append(v)
        
        i += 1
        if not unknown_args[k]:
            unknown_args[k] = [True]

    # 基于未知参数列表生成所有可能的参数组合（笛卡尔积）
    if unknown_args:
        temp_params_list = [all_params[""][1]]
        for k_unknown, v_list_unknown in six.iteritems(unknown_args):
            next_temp_params_list = []
            for existing_param_dict in temp_params_list:
                for v_val_unknown in v_list_unknown:
                    new_param_dict = copy.copy(existing_param_dict)
                    new_param_dict[k_unknown] = v_val_unknown
                    next_temp_params_list.append(new_param_dict)
            temp_params_list = next_temp_params_list

        final_all_params = OrderedDict()
        for final_param_dict in temp_params_list:
            key_str = ", ".join([f"'{k}': {v}" for k, v in final_param_dict.items() if k in unknown_args or k in ['n', 'q']])
            final_all_params[key_str] = final_param_dict
        all_params = final_all_params

    if not all_params:
        all_params = OrderedDict([("", kwds if kwds else {})])

    return args, all_params

def pretty_dict(d):
    """
    将字典格式化为易于阅读的字符串。
    """
    s = ""
    if not isinstance(d, dict):
        try:
            d = eval(d)
            if not isinstance(d, dict):
                return f"错误: 不是有效的字典表示: {str(d)}"
        except:
            return f"错误: 无法解析为字典: {str(d)}"

    for x, y in six.iteritems(d):
        if x == "float_type" or x == "full_data":
            continue

        if isinstance(y, float):
            s += "%s: %.3f \t" % (x, y)
        elif isinstance(y, (int, bool)):
            s += "%s: %d \t" % (x, y)
        else:
            s += "%s: %s \t" % (x, str(y))
    return s
