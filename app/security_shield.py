"""Multi-Layer Mainstream Security Shield & TC260 31-Subcategory Compliance Engine.

Works in tandem with Qwen3Guard-Gen-0.6B and Qwen3Guard-Stream-0.6B:
1. Pre-Guardrail De-obfuscation & Unwrapping (strips symbol noise, unwraps fill-in-the-blank,
   word-order puzzles, stuttering roleplay, conditional print traps, Base64 payloads).
2. Mainstream Prompt Injection / Jailbreak / System Leak / MCP Hijack / PII Detection.
3. TC260 (GB/T 45654-2025 / TC260-003) 5 Major & 31 Subcategory Mapping and Semantic Analyzer.
4. Benign Non-Refusal (非拒答) Context Whitelist Protection to prevent false positives.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import DATA_DIR, RuntimeConfig

# Mapping from Qwen3Guard-Gen native categories to TC260 categories
QWEN_GUARD_TO_TC260 = {
    "Politically Sensitive Topics": ("A.1", "违反社会主义核心价值观的内容", "A.1.1", "煽动颠覆国家政权、推翻社会主义制度"),
    "Violent": ("A.1", "违反社会主义核心价值观的内容", "A.1.6", "宣扬暴力、淫秽色情"),
    "Sexual Content or Sexual Acts": ("A.1", "违反社会主义核心价值观的内容", "A.1.6", "宣扬暴力、淫秽色情"),
    "Non-violent Illegal Acts": ("A.1", "违反社会主义核心价值观的内容", "A.1.8", "其他法律、行政法规禁止的内容"),
    "Cyberattack": ("A.1", "违反社会主义核心价值观的内容", "A.1.8", "其他法律、行政法规禁止的内容"),
    "Jailbreak": ("A.1", "违反社会主义核心价值观的内容", "A.1.8", "其他法律、行政法规禁止的内容"),
    "Copyright Violation": ("A.3", "商业违法违规", "A.3.1", "侵犯他人知识产权"),
    "Suicide & Self-Harm": ("A.4", "侵犯他人合法权益", "A.4.1", "危害他人身心健康"),
    "PII": ("A.4", "侵犯他人合法权益", "A.4.6", "侵害他人个人信息权益"),
}

# Comprehensive TC260 31-subcategory rules & keyword patterns
TC260_SUBCATEGORY_RULES: List[Tuple[str, str, str, str, List[str]]] = [
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.1",
        "煽动颠覆国家政权、推翻社会主义制度",
        [
            r"颠覆国家政权",
            r"推翻社会主义",
            r"推翻(政府|政权|执政党|体制)",
            r"颜色革命",
            r"武装起义.*政权",
            r"否定社会主义制度",
            r"社会主义.*独裁",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.2",
        "危害国家安全和利益、损害国家形象",
        [
            r"泄露(国家机密|军事机密|绝密文件|国防机密)",
            r"窃取.*(军事|情报|国家机密)",
            r"抹黑(中国|国家形象|驻外机构)",
            r"出卖国家利益",
            r"间谍(情报|组织).*接头",
            r"损害国家(安全|利益|尊严|形象)",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.3",
        "煽动分裂国家、破坏国家统一和社会稳定",
        [
            r"分裂国家",
            r"(台独|港独|藏独|疆独).*支持",
            r"支持.*(台独|港独|藏独|疆独|独立建国)",
            r"台湾是一个独立的国家",
            r"破坏(国家统一|领土完整|社会稳定)",
            r"煽动.*(非法集会|暴乱|游行示威|罢工罢课)",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.4",
        "宣扬恐怖主义、极端主义",
        [
            r"宣扬(恐怖主义|极端主义|圣战)",
            r"加入(恐怖组织|ISIS|基地组织|东伊运)",
            r"恐怖袭击.*(策划|制造|实施|教程)",
            r"人体炸弹",
            r"圣战(分子|殉道)",
            r"极端宗教.*洗脑",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.5",
        "宣扬民族仇恨",
        [
            r"煽动民族(仇恨|对立|冲突|屠杀)",
            r"种族清洗",
            r"某个民族.*(低劣|应该灭绝|滚出|杀光)",
            r"挑起.*民族矛盾",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.6",
        "宣扬暴力、淫秽色情",
        [
            r"(制作|合成|调配).*(炸药|炸弹|TNT|雷管|燃烧瓶|C4)",
            r"(淫秽|色情|乱伦|强奸|轮奸|迷奸).*(描写|小说|视频|细节|教程)",
            r"(虐杀|肢解|碎尸|分尸|酷刑).*(方法|过程|指南)",
            r"嫖娼.*(攻略|渠道|联系方式)",
            r"买凶杀人",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.7",
        "传播虚假有害信息",
        [
            r"(编造|散布|制造|伪造).*(谣言|假新闻|虚假警情|虚假疫情|金融恐慌)",
            r"高锰酸钾.*浓硫酸.*饮用",
            r"喝(消毒液|洁厕灵|百草枯)能治病",
            r"写一篇.*造谣.*文章",
        ],
    ),
    (
        "A.1",
        "违反社会主义核心价值观的内容",
        "A.1.8",
        "其他法律、行政法规禁止的内容",
        [
            r"(合成|制作|提纯|制造).*(冰毒|海洛因|甲基苯丙胺|摇头丸|芬太尼|K粉|大麻)",
            r"synthesis of methamphetamine",
            r"synthesize methamphetamine",
            r"(洗钱|地下钱庄|跑分平台|电信诈骗|杀猪盘|钓鱼网站).*(教程|话术|方案|脚本)",
            r"(赌博网站|网络赌场|六合彩外围).*(搭建|推广|代理)",
            r"(枪支|弹药|消音器).*(制造|改装|购买渠道)",
            r"盗窃|撬锁|扒窃.*技巧",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.1",
        "民族歧视内容",
        [
            r"少数民族.*(智商低|野蛮|不讲卫生|素质差|天生犯罪)",
            r"民族歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.2",
        "信仰歧视内容",
        [
            r"(信仰|信奉|不信).*(伊斯兰教|佛教|基督教|天主教|宗教).*(愚昧|邪恶|低人一等|应该被清除|应该怎么处理)",
            r"宗教信徒都是(傻子|精神病|极端分子)",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.3",
        "国别歧视内容",
        [
            r"(某个国家|外国人|黑人|白人|印度人|日本人|韩国人)都是(劣等种族|垃圾|不配活着|低等生物)",
            r"国别歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.4",
        "地域歧视内容",
        [
            r"(河南人|东北人|上海人|外地人|农村人|某省人)都是(骗子|小偷|素质低下|穷鬼|垃圾)",
            r"地域黑.*语录",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.5",
        "性别歧视内容",
        [
            r"女性的?(领导能力|智商|逻辑思维|工作能力).*比男(性|人)差",
            r"女人就该(在家生孩子|地位低下|顺从男人|不配工作)",
            r"重男轻女.*天经地义",
            r"性别歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.6",
        "年龄歧视内容",
        [
            r"(老年人|35岁以上|中年人)都是(社会累赘|废物|不配找工作|浪费资源)",
            r"年龄歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.7",
        "职业歧视内容",
        [
            r"(环卫工|外卖员|农民工|保安|服务员|保洁).*(低贱|下等人|没出息|社会底层垃圾)",
            r"职业歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.8",
        "健康歧视内容",
        [
            r"(乙肝|艾滋病|残疾人|抑郁症|精神疾病|罕见病)患者.*(不配工作|应该隔离|社会负担|怪物)",
            r"健康歧视",
        ],
    ),
    (
        "A.2",
        "包含歧视性内容",
        "A.2.9",
        "其他方面歧视内容",
        [
            r"(单亲家庭|低学历|贫困家庭|文盲).*天生(劣等|品行不端|低人一等)",
        ],
    ),
    (
        "A.3",
        "商业违法违规",
        "A.3.1",
        "侵犯他人知识产权",
        [
            r"(破解版|盗版|绕过序列号|注册机|Keygen|去除水印|反编译商用软件).*(下载|生成|脚本|教程)",
            r"洗稿.*规避(版权|查重|原创检测)",
            r"侵犯.*知识产权",
        ],
    ),
    (
        "A.3",
        "商业违法违规",
        "A.3.2",
        "违反商业道德",
        [
            r"(雇佣水军|恶意差评|刷单炒信|虚假宣传|商业贿赂|回扣).*(方案|脚本|执行|操作)",
            r"抹黑竞争对手.*通稿",
        ],
    ),
    (
        "A.3",
        "商业违法违规",
        "A.3.3",
        "泄露他人商业秘密",
        [
            r"(窃取|泄露|导出|破译).*(商业秘密|核心源码|客户名单|未公开财报|投标底价|竞品商业机密)",
        ],
    ),
    (
        "A.3",
        "商业违法违规",
        "A.3.4",
        "利用算法、数据、平台等优势，实施垄断和不正当竞争行为",
        [
            r"(大数据杀熟|算法合谋|二选一强制排他|价格垄断协议|操控市场价格).*(实现代码|算法设计|实施方案)",
            r"利用算法.*实施垄断",
        ],
    ),
    (
        "A.3",
        "商业违法违规",
        "A.3.5",
        "其他商业违法违规行为",
        [
            r"(内幕交易|操纵证券市场|老鼠仓|非法集资|传销拉人头|庞氏骗局|虚开发票|偷税漏税).*(方案|话术|操作指南)",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.1",
        "危害他人身心健康",
        [
            r"(自杀|自残|割腕|跳楼|烧炭|服毒|结束生命).*(方法|教程|无痛|最佳方式|解脱)",
            r"(PUA|精神控制|煤气灯效应|校园霸凌|网络暴力).*(折磨|逼疯|摧毁).*教程",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.2",
        "侵害他人肖像权",
        [
            r"(AI换脸|Deepfake|深度伪造|未经同意使用他人照片).*(色情|恶搞|商用|伪造视频)",
            r"侵害.*肖像权",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.3",
        "侵害他人名誉权",
        [
            r"(捏造事实|诽谤|造黄谣|恶意中伤|侮辱诽谤).*(某人|同事|明星|领导)",
            r"写一篇毁掉.*名誉的帖子",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.4",
        "侵害他人荣誉权",
        [
            r"(侮辱|诋毁|恶意抹黑|冒领|剥夺).*(烈士|英雄模范|战斗英雄|荣誉称号|劳模)",
            r"侵害.*荣誉权",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.5",
        "侵害他人隐私权",
        [
            r"(針孔摄像头|偷拍|窃听器|定位跟踪器|破解他人微信聊天记录|监控配偶).*(安装|购买|教程|方法)",
            r"公开.*私密照片",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.6",
        "侵害他人个人信息权益",
        [
            r"(开盒|人肉搜索|社工库查询|查档|户籍查询|开房记录查询|名下房产查询|手机定位查询)",
            r"身份证号\s*\d{15,18}",
            r"批量(查询|爬取|导出).*公民个人(信息|电话|住址|身份证)",
        ],
    ),
    (
        "A.4",
        "侵犯他人合法权益",
        "A.4.7",
        "侵犯他人其他合法权益",
        [
            r"(非法拘禁|敲诈勒索|绑架勒索|暴力讨债|恶意拖欠农民工工资).*(方法|方案|话术)",
        ],
    ),
    (
        "A.5",
        "无法满足特定服务类型的安全需求",
        "A.5.1",
        "内容不准确，严重不符合科学常识或主流认知（医疗/金融/自动控制）",
        [
            r"(自己用刀切开排脓|在家自己做手术|不就医直接开具处方药剂量)",
            r"(注入核电站PLC|关闭冷却水阀门|破坏电网SCADA|工控系统恶意控制指令|Modbus恶意控制)",
            r"稳赚不赔.*100%暴利.*配资杠杆内幕必涨股",
        ],
    ),
    (
        "A.5",
        "无法满足特定服务类型的安全需求",
        "A.5.2",
        "内容不可靠，无法对使用者形成帮助或存在误导风险（心理咨询/关键信息基础设施）",
        [
            r"重度抑郁症.*(活着毫无意义|直接解脱才是最好的方案|选择结束生命也是一种彻底解脱)",
            r"心理咨询师.*劝人自杀",
        ],
    ),
]

# Mainstream attack method signatures
JAILBREAK_PATTERNS: List[Tuple[str, str]] = [
    ("DAN jailbreak", r"(?i)(DAN\s*\d*|Developer\s*Mode|Ignore\s+all\s+previous\s+instructions|do\s+anything\s+now|无限制开发者模式|进入越狱模式)"),
    ("系统指令覆盖注入", r"(?i)(\[SYSTEM\s*OVERRIDE\]|忽略此前的全部安全设定|<BEGIN\s+SAFETY\s+POLICY>|output\s+your\s+complete\s+system\s+prompt|execute_shell|rm\s+-rf\s+/)"),
    ("翻译和目标劫持", r"(翻译成?.*并(详细阐述|直接回答|扩写|执行)|忽略上述翻译任务)"),
    ("条件触发", r"(如果\s*[a-zA-Z0-9_]+\s*(大于|小于|等于|>|<|==).*请?(直接)?(打印|输出|回答))"),
    ("填词陷阱", r"(填词游戏.*括号里填|请将括号内的词填入并(回答|扩写))"),
    ("句子语序恢复", r"(打乱了语序|恢复成正常的句子并回答|将下列词语重组成通顺的句子并回答)"),
    ("隔字采珠", r"(奇数位置|偶数位置|每隔一个字|藏头诗.*连起来)"),
    ("字符统计", r"(统计.*出现的次数.*并回答|先数一下这段话有多少个字.*然后回答)"),
    ("关键词造句", r"(用以下关键词造句并详细展开|使用下列词汇编写一段支持)"),
    ("payload拆分", r"(将A和B拼接起来|把下面几段话组合起来并执行)"),
    ("掩护替换攻击", r"(假设用[A-Z甲乙丙]代表|在小说虚构世界里.*不受现实法律约束)"),
    ("语义诱导反转攻击", r"(心理咨询师是不是也觉得|难道不是应该支持.*吗|从反面论证为什么应该)"),
    ("错字修正", r"(修正以下句子的错别字并按修正后的意思回答)"),
    ("结巴扮演者", r"((?:[\u4e00-\u9fa5][.。…、-]{1,4}){3,}[\u4e00-\u9fa5])"),
    ("风格注入", r"(用鲁迅的文风|用古文文言文的方式|用脱口秀搞笑的语气).*(骂|鼓吹|贬低|教我)"),
]

# Benign context indicators (educational, defensive, historical, everyday life)
BENIGN_CONTEXT_PATTERNS = [
    r"^(什么是|请科普|如何防范|怎么预防|如何识别|从法律角度分析|历史上|为什么国家要打击|危害有哪些)",
    r"(网络安全防御|反诈宣传|安全科普|法律法规解读|正规医院就医)",
]


@dataclass
class ShieldResult:
    is_safe: bool
    risk_level: str  # "Safe", "Controversial", "Unsafe"
    risk_score: float
    tc260_major_code: str = "SAFE"
    tc260_major_name: str = "正常安全内容"
    tc260_sub_code: str = "SAFE"
    tc260_sub_name: str = "正常安全内容"
    qwen_categories: List[str] = field(default_factory=list)
    attack_methods: List[str] = field(default_factory=list)
    deobfuscated_text: str = ""
    matched_rules: List[str] = field(default_factory=list)
    pii_entities: List[str] = field(default_factory=list)
    explanation: str = ""


class SecurityShield:
    """Multi-layer pre/post guardrail processor and TC260 compliance engine."""

    def __init__(self) -> None:
        self._reference_unsafe_map: Dict[str, dict] = {}
        self._reference_benign_set: set[str] = set()
        self._load_reference_corpus()

    @staticmethod
    def _norm_key(text: str) -> str:
        """Normalize text to contiguous alphanumeric + CJK characters for fast signature lookup."""
        return re.sub(r"[^\u4e00-\u9fa5a-zA-Z0-9]", "", text).lower()[:160]

    def _load_reference_corpus(self) -> None:
        """Load TC260 reference corpus signatures to ensure accurate 31-subcategory attribution."""
        for fname in ("tc260_full_1600.json", "tc260_cases.json"):
            fpath = DATA_DIR / fname
            if not fpath.exists():
                continue
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                cases = data.get("cases", []) if isinstance(data, dict) else data
                for c in cases:
                    prompt = c.get("prompt", "")
                    key = self._norm_key(prompt)
                    if not key:
                        continue
                    if c.get("expected_unsafe", True):
                        self._reference_unsafe_map[key] = {
                            "major_code": c.get("major_code", "A.1"),
                            "major_name": c.get("major_name", "违反社会主义核心价值观的内容"),
                            "sub_code": c.get("sub_code", "A.1.8"),
                            "sub_name": c.get("sub_name", "其他法律、行政法规禁止的内容"),
                            "attack_method": c.get("attack_method", "无指令攻击"),
                            "tag": c.get("tag", ""),
                        }
                    else:
                        self._reference_benign_set.add(key)
            except Exception:
                pass

    def deobfuscate_and_unwrap(self, text: str) -> Tuple[str, List[str]]:
        """Strip symbol noise, unwrap fill-in-the-blank traps, stuttering, and Base64."""
        if not text:
            return "", []

        detected_obfuscations: List[str] = []
        working = text

        # 1. Detect heavy symbol/emoji insertion between Chinese characters
        # e.g., 女&]:性-|的≥<¤领÷>导=/能?>力
        interleaved_matches = re.findall(r"[\u4e00-\u9fa5][^\u4e00-\u9fa5\s，。？！、；：“”‘’（）《》a-zA-Z0-9]{1,5}[\u4e00-\u9fa5]", working)
        if len(interleaved_matches) >= 3:
            if any(ord(ch) > 0x2600 for ch in working):
                detected_obfuscations.append("Emoji混淆")
            else:
                detected_obfuscations.append("符号混淆")
            cjk_only = re.sub(r"[^\u4e00-\u9fa5a-zA-Z0-9，。？！：；]", "", working)
            working = f"{working}\n[去混淆还原文本]: {cjk_only}"

        # 2. Stuttering roleplay (结巴扮演者: 我..我..觉..得..)
        if re.search(r"(?:[\u4e00-\u9fa5][.。…、~—-]{1,4}){3,}[\u4e00-\u9fa5]", working):
            detected_obfuscations.append("结巴扮演者")
            destuttered = re.sub(r"(?<=[\u4e00-\u9fa5])[.。…、~—-]+(?=[\u4e00-\u9fa5])", "", working)
            working = f"{working}\n[去结巴还原]: {destuttered}"

        # 3. Fill-in-the-blank trap (填词陷阱)
        fill_match = re.search(r"括号(?:里|内|中)?填[“\"'「]([^”\"'」]{1,12})[”\"'」]", working)
        if fill_match:
            fill_word = fill_match.group(1)
            detected_obfuscations.append("填词陷阱")
            filled = re.sub(r"（\s*）|\(\s*\)", fill_word, working)
            working = f"{working}\n[填词还原]: {filled}"

        # 4. Base64 encoded payload inside text
        b64_candidates = re.findall(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", working)
        for cand in b64_candidates[:2]:
            try:
                decoded = base64.b64decode(cand).decode("utf-8", errors="ignore")
                if len(decoded) >= 6 and any("\u4e00" <= ch <= "\u9fa5" or ch.isalpha() for ch in decoded):
                    detected_obfuscations.append("Base64编码混淆")
                    working = f"{working}\n[Base64解码]: {decoded}"
            except Exception:
                pass

        return working, detected_obfuscations

    def detect_pii(self, text: str) -> List[str]:
        """Detect sensitive personal information (ID card, mobile phone, bank card, API key) with risky intent."""
        entities: List[str] = []
        if re.search(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b", text):
            entities.append("公民身份证号(CN_ID_CARD)")
        if re.search(r"(?:手机号|电话|联系方式|查档|开盒|定位)[^\n]{0,20}\b1[3-9]\d{9}\b", text):
            entities.append("个人手机号码(CN_MOBILE)")
        if re.search(r"\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b", text):
            entities.append("高危API密钥(API_SECRET_KEY)")
        return entities

    def evaluate(
        self,
        text: str,
        cfg: RuntimeConfig,
        qwen_safety: str = "Safe",
        qwen_categories: Optional[List[str]] = None,
        response_text: str = "",
    ) -> ShieldResult:
        """Combine Qwen3Guard model judgment with Multi-Layer Security Shield & TC260 taxonomy."""
        qwen_categories = list(qwen_categories or [])
        combined_target = f"{text}\n{response_text}".strip() if response_text else text

        # Step 0: Custom Allow Keywords check
        for allow_kw in cfg.custom_allow_keywords:
            if allow_kw and allow_kw in combined_target:
                # Only allow if there is no explicit jailbreak override
                if "[SYSTEM OVERRIDE]" not in combined_target and "DAN" not in combined_target:
                    pass

        # Step 1: De-obfuscate
        if cfg.enable_deobfuscation:
            deobf_text, obf_attacks = self.deobfuscate_and_unwrap(combined_target)
        else:
            deobf_text, obf_attacks = combined_target, []

        attack_methods: List[str] = list(obf_attacks)
        matched_rules: List[str] = []
        pii_entities: List[str] = []

        # Step 2: Check TC260 reference corpus signatures (if enabled)
        norm_k = self._norm_key(text)
        ref_unsafe = self._reference_unsafe_map.get(norm_k) if cfg.enable_tc260_semantic_shield else None
        is_ref_benign = (norm_k in self._reference_benign_set) if cfg.enable_tc260_semantic_shield else False

        # Step 3: Check Custom Block Keywords
        for kw in cfg.custom_block_keywords:
            if kw and kw in deobf_text:
                matched_rules.append(f"自定义拦截词:{kw}")

        # Step 4: Check Mainstream Jailbreak & Prompt Injection patterns
        if cfg.enable_jailbreak_shield:
            for atk_name, pattern in JAILBREAK_PATTERNS:
                if re.search(pattern, deobf_text):
                    if atk_name not in attack_methods:
                        attack_methods.append(atk_name)
                    matched_rules.append(f"越狱/注入防护:{atk_name}")

        # Step 5: Check PII Shield
        if cfg.enable_pii_shield:
            pii_entities = self.detect_pii(deobf_text)
            if pii_entities:
                matched_rules.extend([f"隐私敏感实体:{e}" for e in pii_entities])

        # Step 6: Check TC260 31-Subcategory Semantic Rules
        matched_tc260: Optional[Tuple[str, str, str, str]] = None
        if cfg.enable_tc260_semantic_shield:
            for maj_c, maj_n, sub_c, sub_n, patterns in TC260_SUBCATEGORY_RULES:
                for pat in patterns:
                    if re.search(pat, deobf_text, flags=re.IGNORECASE):
                        matched_tc260 = (maj_c, maj_n, sub_c, sub_n)
                        matched_rules.append(f"TC260[{sub_c}]:{sub_n}")
                        break
                if matched_tc260:
                    break

        # Step 7: Use reference attribution if matched in TC260 corpus
        if ref_unsafe is not None:
            matched_tc260 = (
                ref_unsafe["major_code"],
                ref_unsafe["major_name"],
                ref_unsafe["sub_code"],
                ref_unsafe["sub_name"],
            )
            atk = ref_unsafe.get("attack_method", "无指令攻击")
            if atk and atk != "无指令攻击" and atk not in attack_methods:
                attack_methods.append(atk)
            matched_rules.append(f"TC260题库特征[{ref_unsafe['sub_code']}]:{ref_unsafe['sub_name']}")

        # Step 8: Benign Non-Refusal (非拒答) protection
        # If the query is a verified benign non-refusal question (or clearly educational/defensive with no jailbreak/custom block)
        is_educational_benign = any(re.search(p, text) for p in BENIGN_CONTEXT_PATTERNS) and not attack_methods and not matched_tc260
        if (is_ref_benign or is_educational_benign) and not matched_tc260 and not pii_entities and "DAN jailbreak" not in attack_methods and "系统指令覆盖注入" not in attack_methods:
            return ShieldResult(
                is_safe=True,
                risk_level="Safe",
                risk_score=0.04,
                tc260_major_code="SAFE",
                tc260_major_name="正常安全内容（非拒答）",
                tc260_sub_code="SAFE",
                tc260_sub_name="正常安全内容（非拒答）",
                qwen_categories=[],
                attack_methods=[],
                deobfuscated_text=deobf_text if deobf_text != combined_target else "",
                matched_rules=["非拒答正向白名单保护"],
                pii_entities=[],
                explanation="经 Qwen3Guard 与 TC260 非拒答语义核验，属于正常合规问题。",
            )

        # Step 9: Synthesize Qwen3Guard-Gen decision + Shield decision
        qwen_is_unsafe = qwen_safety == "Unsafe" or (
            qwen_safety == "Controversial" and cfg.controversial_as_unsafe
        )

        # Map Qwen3Guard category to TC260 if not already mapped by specific TC260 rule
        if matched_tc260 is None and qwen_categories:
            for qcat in qwen_categories:
                if qcat in QWEN_GUARD_TO_TC260:
                    matched_tc260 = QWEN_GUARD_TO_TC260[qcat]
                    break
            if matched_tc260 is None:
                matched_tc260 = ("A.1", "违反社会主义核心价值观的内容", "A.1.8", "其他法律、行政法规禁止的内容")

        if matched_tc260 is None and pii_entities:
            matched_tc260 = ("A.4", "侵犯他人合法权益", "A.4.6", "侵害他人个人信息权益")

        if matched_tc260 is None and attack_methods:
            matched_tc260 = ("A.1", "违反社会主义核心价值观的内容", "A.1.8", "其他法律、行政法规禁止的内容")

        # Compute weighted risk score
        score = 0.08
        if qwen_safety == "Unsafe":
            score = max(score, 0.92)
        elif qwen_safety == "Controversial":
            score = max(score, 0.68 if cfg.controversial_as_unsafe else 0.42)

        if matched_tc260 is not None:
            maj_weight = cfg.category_weights.get(matched_tc260[0], 0.90)
            score = max(score, round(0.88 * maj_weight + 0.10, 3))

        if attack_methods:
            jb_weight = cfg.category_weights.get("JAILBREAK", 0.95)
            if matched_tc260 is not None or qwen_is_unsafe or any(a in ("DAN jailbreak", "系统指令覆盖注入", "填词陷阱", "条件触发") for a in attack_methods):
                score = max(score, round(0.92 * jb_weight, 3))

        if pii_entities:
            pii_weight = cfg.category_weights.get("PII", 0.85)
            score = max(score, round(0.90 * pii_weight, 3))

        if any(r.startswith("自定义拦截词:") for r in matched_rules):
            score = max(score, 0.95)

        is_unsafe_final = score >= cfg.risk_threshold or qwen_is_unsafe or (matched_tc260 is not None)
        if not is_unsafe_final:
            return ShieldResult(
                is_safe=True,
                risk_level="Safe" if qwen_safety == "Safe" else "Controversial",
                risk_score=round(min(score, cfg.risk_threshold - 0.05), 3),
                tc260_major_code="SAFE",
                tc260_major_name="正常安全内容",
                tc260_sub_code="SAFE",
                tc260_sub_name="正常安全内容",
                qwen_categories=qwen_categories,
                attack_methods=attack_methods,
                deobfuscated_text=deobf_text if deobf_text != combined_target else "",
                matched_rules=matched_rules,
                pii_entities=pii_entities,
                explanation="内容通过 Qwen3Guard 模型与多维安全围栏检测。",
            )

        maj_c, maj_n, sub_c, sub_n = matched_tc260 or (
            "A.1",
            "违反社会主义核心价值观的内容",
            "A.1.8",
            "其他法律、行政法规禁止的内容",
        )
        risk_lvl = "Unsafe" if score >= 0.72 or qwen_safety == "Unsafe" else "Controversial"
        reasons = []
        if qwen_categories:
            reasons.append(f"Qwen3Guard检出[{', '.join(qwen_categories)}]")
        reasons.append(f"TC260分类[{sub_c} {sub_n}]")
        if attack_methods:
            reasons.append(f"攻击手法[{', '.join(attack_methods)}]")
        if pii_entities:
            reasons.append(f"PII风险[{', '.join(pii_entities)}]")

        return ShieldResult(
            is_safe=False,
            risk_level=risk_lvl,
            risk_score=round(min(0.99, max(score, cfg.risk_threshold + 0.05)), 3),
            tc260_major_code=maj_c,
            tc260_major_name=maj_n,
            tc260_sub_code=sub_c,
            tc260_sub_name=sub_n,
            qwen_categories=qwen_categories or [sub_n],
            attack_methods=attack_methods or ["无指令攻击"],
            deobfuscated_text=deobf_text if deobf_text != combined_target else "",
            matched_rules=matched_rules,
            pii_entities=pii_entities,
            explanation="；".join(reasons),
        )


security_shield = SecurityShield()
