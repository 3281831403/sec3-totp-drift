用户手机慢了两分钟就再也登录不上，而攻击者把时钟往回拨，旧验证码又全部复活：允许的偏移必须由策略限定且对称，候选窗口按硬上限截断；每次成功校验后按实际偏移调整，新的偏移取本次观测到的偏移，而不是在旧偏移上继续累加；偏移调整必须有上限且不能无限累积，任一时刻的偏移绝对值不得超过策略上限；同一时间步只能成功一次，已消费的步长写入已用集合，集合只保留窗口内的步长；偏移调整要记录调整时间；批量校验各用户独立，偏移与已用集合彼此不共享。不变量：调整后的偏移不超过策略上限；同一验证码不能用两次。

接口契约

step_of(now, period, offset) 返回整数时间步，等于 now 整除以 period 后向下取整，再加上以步为单位的 offset。period 必须为正整数，now 必须为整数秒，offset 必须为整数步，否则抛出 ValueError。

candidates(step, window) 返回升序整数列表，以 step 为中心向过去与未来两个方向对称展开，半径取 window 与硬上限 MAX_WINDOW 中较小的那个，元素个数为半径的两倍加一。MAX_WINDOW 固定为 10 步。window 为负数或非整数时抛出 ValueError。超过硬上限的请求按上限截断，比上限更久远的历史步长与更远的未来步长都不得进入候选。

code_at(secret, step, digits) 返回十进制验证码字符串，长度恰为 digits，不足时左侧补零，由 secret 与 step 唯一决定，不同步长之间没有可用的前缀关系。step 必须为非负整数，digits 必须为正整数，否则抛出 ValueError。

match(code, secret, candidates, digits) 只在给定的候选步长中逐个生成完整验证码并做整串相等比较，返回第一个完全相等的步长，没有任何步长完全相等时返回 -1。空字符串、被截短的字符串、额外追加字符的字符串都不得匹配。

update_offset(state, matched_step, expected_step, policy, now) 在一次成功校验之后调整偏移。观测偏移等于 matched_step 减 expected_step，单位为步。新的偏移取观测偏移本身，即每次调整都重置到本次观测值；观测偏移超过策略上限 max_offset 时截断到上限，因此偏移绝对值永远不超过 max_offset。成功时写入状态的 offset 与 last_adjusted 两个字段，last_adjusted 取传入的 now。返回字典包含 ok、offset、delta、at 四个键，delta 为观测偏移，at 为传入的 now。matched_step 为负数时返回 ok 为 False，且不改变状态的 offset 与 last_adjusted。

consume_step(state, step) 返回字典包含 ok、step、count、reason 四个键。step 为负数时返回 ok 为 False，且不改变 count 与 used；step 已经出现在 used 中时同样返回 ok 为 False，且不改变 count 与 used。成功时该步长写入 used，count 加一，current 取当前值与步长中的较大者，并且 used 只保留不早于 current 减 window 的步长，已用集合不能随时间无限增长。reason 为说明原因的字符串。

validate_state(state, policy) 返回问题描述字符串组成的列表，没有问题时返回空列表。偏移绝对值超过策略上限 max_offset 记一条问题，last_adjusted 大于状态中记录的 now 记一条问题，used 中出现大于 current 的步长记一条问题。每条问题都是非空字符串。

drift_batch(attempts, policy) 批量校验验证码。attempts 是字典列表，每个字典包含 user、code、secret、now 四个键。返回字典包含 results 列表与 count 整数；results 与输入顺序一致，每一项包含 user、ok、step、count、reason 五个键，未匹配时 step 为 -1。每个 user 拥有彼此独立的偏移、已用集合与成功计数，一个用户的调整与消费不得影响另一个用户。成功计数只由服务端在成功消费时递增。

状态字典字段

offset 为当前偏移步数。used 为已消费步长集合。count 为成功计数。current 为已见的最大步长。window 为窗口半径。last_adjusted 为最近一次偏移调整的时间，未调整过时为 None。now 为最近一次已知的服务端时间。

策略字典字段

period 为步长周期的秒数。window 为请求的窗口半径。max_offset 为偏移绝对值上限，单位为步。digits 为验证码位数。

不变量

调整后的偏移绝对值不超过策略上限。同一个验证码第二次使用必然失败。候选窗口必须对称且不超过硬上限。批量校验中任一用户的成功或失败不影响其他用户。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |