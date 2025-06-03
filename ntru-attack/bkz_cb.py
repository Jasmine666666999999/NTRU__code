# -*- coding: utf-8 -*-

from fpylll import BKZ, Enumeration, EnumerationError
from fpylll.algorithms.bkz import BKZReduction as BKZBase
from fpylll.tools.bkz_stats import dummy_tracer
from fpylll.util import gaussian_heuristic, randint

# 继承并扩展 fpylll 的 BKZ 实现
class BKZReduction(BKZBase):
    """
    一个定制化的 BKZ 算法实现。
    
    主要特性是增加了一个回调函数 `insert_callback`，它在 SVP（最短向量问题）
    求解器找到一个更短的向量并准备将其插入基中时被调用。
    这允许在 BKZ 约化过程中对找到的向量进行实时分析。
    """

    def __init__(self, A):
        """
        初始化 BKZ 约化对象。
        :param A: 一个整数矩阵、GSO 对象或 LLL 对象。
        """
        super(BKZReduction, self).__init__(A)
        self.insert_callback = None # 初始化回调函数为空
        self.call_stack = [] # 用于跟踪 SVP 递归调用的栈

    def get_pruning(self, kappa, block_size, params, tracer=dummy_tracer):
        """
        计算并获取用于 SVP 枚举的剪枝参数。
        
        通过高斯启发式等方法估算枚举半径，以优化搜索过程。
        """
        strategy = params.strategies[block_size]
        radius, re = self.M.get_r_exp(kappa, kappa)
        radius *= self.lll_obj.delta
        r = [self.M.get_r_exp(i, i) for i in range(kappa, kappa + block_size)]
        gh_radius = gaussian_heuristic([x for x, _ in r])
        ge = float(sum([y for _, y in r])) / len(r)

        if (params.flags & BKZ.GH_BND and block_size > 30):
            radius = min(radius, gh_radius * 2**(ge - re) * params.gh_factor)

        return radius, re, strategy.get_pruning(radius, gh_radius * 2**(ge - re))

    def randomize_block(self, min_row, max_row, tracer=dummy_tracer, density=0):
        """
        对基的一个指定块进行随机化处理。
        
        这有助于避免算法陷入局部最优，具体操作包括：
        1. 随机置换指定范围内的行。
        2. 应用一个稀疏的下三角矩阵进行变换。
        """
        if max_row - min_row < 2:
            return

        # 1. 随机置换行
        niter = 4 * (max_row - min_row)
        with self.M.row_ops(min_row, max_row):
            for i in range(niter):
                a = randint(min_row, max_row - 1)
                b = a
                while b == a:
                    b = randint(min_row, max_row - 1)
                self.M.move_row(b, a)

        # 2. 应用稀疏三角变换
        with self.M.row_ops(min_row, max_row):
            for a in range(min_row, max_row - 2):
                for i in range(density):
                    b = randint(a + 1, max_row - 1)
                    s = randint(0, 1)
                    self.M.row_addmul(a, b, 2 * s - 1)
        return

    def svp_preprocessing(self, kappa, block_size, params, tracer=dummy_tracer):
        """
        在执行核心的 SVP 枚举之前，对当前块进行预处理。
        
        预处理通常包括对子块进行 BKZ 约化，以改善基的质量，提高 SVP 成功率。
        """
        clean = True
        clean &= super(BKZReduction, self).svp_preprocessing(kappa, block_size, params, tracer)

        for preproc in params.strategies[block_size].preprocessing_block_sizes:
            prepar = params.__class__(block_size=preproc, strategies=params.strategies, flags=BKZ.GH_BND)
            clean &= self.tour(prepar, kappa, kappa + block_size, tracer=tracer)

        return clean

    def svp_reduction(self, kappa, block_size, params, tracer=dummy_tracer):
        """
        对指定的格基子块执行 SVP（最短向量问题）约化。
        
        这是 BKZ 算法的核心步骤，通过枚举来寻找子格中的短向量。
        如果找到了比当前基向量更短的向量，则会调用 `insert_callback`。
        """
        self.call_stack.append((kappa, block_size))
        self.lll_obj.size_reduction(0, kappa + 1)
        old_first, old_first_expo = self.M.get_r_exp(kappa, kappa)

        remaining_probability, rerandomize = 1.0, False

        while remaining_probability > 1. - params.min_success_probability:
            with tracer.context("preprocessing"):
                if rerandomize:
                    with tracer.context("randomization"):
                        self.randomize_block(kappa + 1, kappa + block_size,
                                             density=params.rerandomization_density, tracer=tracer)
                with tracer.context("reduction"):
                    self.svp_preprocessing(kappa, block_size, params, tracer=tracer)

            with tracer.context("pruner"):
                radius, re, pruning = self.get_pruning(kappa, block_size, params, tracer)

            try:
                enum_obj = Enumeration(self.M)
                with tracer.context("enumeration",
                                    enum_obj=enum_obj,
                                    probability=pruning.expectation,
                                    full=block_size == params.block_size):
                    max_dist, solution = enum_obj.enumerate(kappa, kappa + block_size, radius, re,
                                                            pruning=pruning.coefficients)[0]
                with tracer.context("postprocessing"):
                    # 在插入向量前调用回调函数
                    if self.insert_callback is not None:
                        self.insert_callback(self.call_stack, solution)
                    self.svp_postprocessing(kappa, block_size, solution, tracer=tracer)
                rerandomize = False

            except EnumerationError:
                rerandomize = True

            remaining_probability *= (1 - pruning.expectation)

        self.lll_obj.size_reduction(0, kappa + 1)
        new_first, new_first_expo = self.M.get_r_exp(kappa, kappa)
        clean = old_first <= new_first * 2**(new_first_expo - old_first_expo)
        self.call_stack.pop()
        return clean
