import os, json, re, argparse
import concurrent.futures

RE_INDENT = re.compile(r'^\s*')
RE_START_MATCH = re.compile(r"START\s+#?(\d+)")
RE_END_MATCH = re.compile(r'^\s*END\b')
RE_SPACE = re.compile(r'(\s+)')
RE_OP = re.compile(r'([ \t]*[=][ \t]*)') 
RE_C = re.compile(r"^C(\d+)$")
RE_CYP = re.compile(r"^CYP(\d+)$")
RE_TS = re.compile(r"^TS(\d+)$")
RE_WORD = re.compile(r"[\$]?[A-Za-z0-9_]+")
RE_PARTS = re.compile(r"^([A-Za-z]+)(\d+)([A-Za-z]*)$")
RE_TPH = re.compile(r"^TPH(\d+)?([A-D])?$")
RE_TAGS = re.compile(r'(<(?:START|\$\d+)>)') 
RE_SWAP = re.compile(r'([^ \t\n<>]+)(\s*)<>\s*([^ \t\n<>]+)')
RE_EQUATION = re.compile(r'\b([A-Za-z0-9_]+)\s*([<+=])\s*(.*?)(?=\s+\b[A-Za-z0-9_]+\s*[<+=]|$)')

RE_SET = re.compile(r"\b(SET)\s+([A-Za-z0-9_]+)\s+([#$]?[A-Za-z0-9]+)\b")
#RE_SET = re.compile(r"\b(SET)(\s[A-Za-z0-9]\s*)([\$][a-zA-Z0-9]+)\b")
RE_D_GROUP = re.compile(r"\b(D\d+[A-Z]?(?:_2)?)(\s*[<=]+\s*)([#$]?[A-Za-z0-9]+)(\s*)")
RE_D_LETTER_MATCH = re.compile(r"^D(\d+)([A-Z])$")
RE_D_LETTER_1 = re.compile(r"(D\d+[A-Z])(\s*[<=+&-]+\s*)([#$][a-zA-Z0-9]+)")
RE_D_LETTER_2 = re.compile(r"\b([0-9A-Za-z]{2,3})(\s*[=+<&-]+\s*)(D\d+[A-Z])\b")
RE_D5N = re.compile(r"\b(D5[A-Z])(\s*[=]+\s*)([^ \n]+)")
RE_D5N_MATCH = re.compile(r"^D5([A-Z])$")
RE_D5N_RHO = re.compile(r"\b(D5[A-Z])\b")
RE_D5 = re.compile(r"\bD5([<])([A-Za-z0-9]+)\b")
RE_EXC_D5 = re.compile(r'\b(D5)\b(?:\s*[<=]\s*[$#]?([A-Za-z0-9_]+))?')
RE_TPH_GROUP = re.compile(r'\b(TPH(?:[12][A-D])?(?:_2)?)\b(?:\s*[<=]\s*[$#]?([A-Fa-f0-9]+))?')
RE_TP_GROUP = re.compile(r'\b(TP(?:1_2|2_2|1|2)?)\b(?:\s*[<=]\s*\$([A-Fa-f0-9]+))?')
RE_TP_MATCH = re.compile(r"TP\d+_\d+")
RE_XT = re.compile(r'\b(XT)(?:1-15)?\b(\s*[<=]\s*[$#?]([A-Za-z0-9]))?')

def load_rules(filepath="pat_rule.json"):
    with open(filepath, "r", encoding="utf-8") as f: 
        r = json.load(f)
    sm = r.get("simple", {})
    cm = r.get("complex", {})

    for k, v in cm.items():
        if isinstance(v, dict) and "pattern" in v:
            v["compiled_pattern"] = re.compile(v["pattern"])
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and "pattern" in item and isinstance(item["pattern"], str):
                    item["compiled_pattern"] = re.compile(item["pattern"])

    for k in ["XSK", "YSK"]:
        if k in cm and "pattern" in cm[k]:
            cm[k]["compiled_pattern"] = re.compile(cm[k]["pattern"].strip('^$'))

    for k in ["DRE", "CPE"]:
        if k in cm:
            for var, rule in cm[k].items():
                rule["compiled_pattern"] = re.compile(rf"\b({var})(\s*=\s*)({re.escape(rule['target'])})\b")

    group_b = {k: v if isinstance(v, list) else [v] for k, v in cm.items() if k in ["JNI", "JSI", "JL"]}
    if group_b:
        keys_re = "|".join(group_b.keys())
        all_exts = set()
        for rules in group_b.values():
            for r in rules:
                exts = r.get("extra")
                exts_list = exts if isinstance(exts, list) else [exts] if exts else []
                for e in exts_list:
                    if e and e.strip():
                        all_exts.add(re.escape(e.strip()))
        
        suf_re = rf"(?:\s*({'|'.join(sorted(all_exts, key=len, reverse=True))})(?!\w))?" if all_exts else r"()"
        cm["GROUP_B_COMPILED"] = re.compile(rf"\b({keys_re})(\d+){suf_re}")
        cm["GROUP_B_RULES"] = group_b

    return sm, cm

def preprocess(text):
    lines, reg_lines, cleaned, output = text.splitlines(), [], [], []
    extracted_dre_cpe = [] 
    in_reg, in_start = False, False 
    first_start = True
    
    for line in lines:
        s = line.strip()
        if s.startswith("REGISTER"): 
            in_reg = True 
        elif in_reg and "TREFRESH" in s: 
            in_reg = False 
            cleaned.append(line) 
        elif in_reg:
            if s.startswith(("DRE", "CPE")):
                extracted_dre_cpe.append(line.strip())
            else:
                reg_lines.append(line)
        elif s.startswith("INSERT"):
            extracted_dre_cpe.append("\n"+line.strip())
        else: 
            cleaned.append(line)

    reg_inserted = False 
    for line in cleaned:
        s, blk = line.strip(), (RE_INDENT.match(line).group(0) if line else "")
    
        if not reg_inserted and "TREFRESH" in s and reg_lines:
            output.extend([blk + "DATA 0"] + reg_lines + [blk + " ", line])
            reg_inserted = True
            continue
            
        if s.startswith("XY"):
            output.append(line)
            output.append("END")
            continue
            
        if s.startswith("START"):
            if in_start:
                last_cmd = ""
                for prev in reversed(output):
                    if prev.strip():
                        last_cmd = prev.strip()
                        break
                if last_cmd.startswith("STPS"):
                    output.append(blk + "NOP")
                if not last_cmd.startswith(("STPS", "STSPS", "HALT", "MODULE END")):
                    output.append(blk + "STPS") 
            m = RE_START_MATCH.match(s)
            
            if first_start:
                output.append(blk + "MICRO1D")
                #for ext in extracted_dre_cpe:
                    #output.append(blk + ext)
                first_start = False
            output.append(blk + (f"<${m.group(1)}>" if m else "<START>"))
            in_start = True
            continue
            
        if s.startswith(("HALT", "MODULE END", "STPS", "STSPS")):
            # 1. 출력물 끝에서 마지막 실제 명령어를 찾음
            last_cmd = ""
            for prev in reversed(output):
                if prev.strip():
                    last_cmd = prev.strip()
                    break

            if last_cmd and not last_cmd.startswith(("HALT", "MODULE END", "STPS", "STSPS", "NOP")):
                output.append(blk + "NOP")
            
            output.append(line)
            continue    
        if s.startswith(("HALT", "MODULE END", "STPS", "STSPS")):
            output.append(line)
            continue
            
        if s == "END":
            output.append(line)
            in_start = False 
            continue
            
        output.append(line)
        
    if in_start: 
        output.append((RE_INDENT.match(output[-1]).group(0) if output else "") + "END")
        
    end_count = 0
    for line in reversed(output):
        s = line.strip()
        if not s: continue 
        if s == "END":
            end_count += 1
            if end_count == 2: break
        else: break 
            
    for _ in range(2 - end_count): output.append("END")
        
    return "\n".join(output)

def _calc_d_idx(num, let, ranges):
    prev_len = sum(len(ranges[f"D{i}"]) for i in range(1, num) if f"D{i}" in ranges and f"D{i}" != "D3")
    return prev_len + ranges[f"D{num}"].index(let) + 1

def _convert_c_token(n, psr_mode):
    if psr_mode and 10 <= n <= 13: return ["PSRPAT PSRA=PSRA+1", "_PSRA=PSRAP1", "_PSRA=PSRAP2", "_PSRA=PSRAP3"][n-10]
    if n == 0: return "RB0"
    if n <= 9: return f"RB{n}"
	if 21 <= n <= 24: return f"CB{n-20}"
    return f"RB{n}"

def _split_hex(hex_str):
        # 1. 특수기호 제거 후 실제 32비트 숫자(정수)로 변환
        clean_hex = hex_str.replace("$", "").replace("#", "")
        if not clean_hex: clean_hex = "0"
        val = int(clean_hex, 16)
        
        # 2. High: 우측으로 18비트 시프트 연산 (>> 18)
        high = val >> 18
        
        # 3. Low: 하위 16비트만 통과시키는 마스킹 연산 (& 0xFFFF)
        low = val & 0xFFFF
        
        # 4. 결과를 대문자 16진수 4자리 문자열(예: "3BCB", "1234")로 예쁘게 포맷팅
        return f"{high:04X}", f"{low:04X}"

def _process_xcs(line):
    def repl_cs(m):
        lhs = m.group(1)            # 좌변
        op = m.group(2)             # 연산자 (<, =, +=)
        rhs = m.group(3).strip()    # 우변
        
        # XCS나 YCS가 없는 일반 수식은 건드리지 않고 그대로 통과
        if 'XCS' not in lhs and 'XCS' not in rhs and 'YCS' not in lhs and 'YCS' not in rhs:
            return m.group(0)
            
        # 변환될 수식들을 담을 리스트 (초기값은 원본 좌변/우변 1세트)
        equations = [(lhs, rhs)]
        
        # 2. XCS 분할 로직 (XC, XS)
        if 'XCS' in lhs or 'XCS' in rhs:
            new_eqs = []
            for l, r in equations:
                # 첫 번째 복사본: 좌/우변의 모든 XCS를 XC로 치환
                new_eqs.append((re.sub(r'\bXCS\b', 'XC', l), re.sub(r'\bXCS\b', 'XC', r)))
                # 두 번째 복사본: 좌/우변의 모든 XCS를 XS로 치환
                new_eqs.append((re.sub(r'\bXCS\b', 'XS', l), re.sub(r'\bXCS\b', 'XS', r)))
            equations = new_eqs # 복제된 수식들로 업데이트
            
        # 3. YCS 분할 로직 (YC, YS)
        if 'YCS' in lhs or 'YCS' in rhs:
            new_eqs = []
            for l, r in equations:
                # 첫 번째 복사본: 좌/우변의 모든 YCS를 YC로 치환
                new_eqs.append((re.sub(r'\bYCS\b', 'YC', l), re.sub(r'\bYCS\b', 'YC', r)))
                # 두 번째 복사본: 좌/우변의 모든 YCS를 YS로 치환
                new_eqs.append((re.sub(r'\bYCS\b', 'YS', l), re.sub(r'\bYCS\b', 'YS', r)))
            equations = new_eqs # 복제된 수식들로 업데이트
            
        # 4. 최종 조립: 독립된 방에서 안전하게 복제된 수식들을 띄어쓰기로 연결
        return " ".join([f"{l}{op}{r}" for l, r in equations])
    
    # 라인 전체에 대해 격리 및 분할 변환 실행
    return RE_EQUATION.sub(repl_cs, line)
        
def _process_regex_rules(line, cm, in_reg=False):
    
    
    line = _process_xcs(line)
    
    
    set_flg = False 
	
    if r_set := cm.get("SET"):
        def repl_set(m):
            nonlocal set_flg
            set_flg = True
            
            target = m.group(2).replace(".", "") # 예: D1A, YH
            val = m.group(3)    # 예: $01, #01
            
            fmt = r_set.get("output", "{word} {content}{val}")
            return fmt.format(word="NOP ", content=target, val=f"={val}")
            
        line = RE_SET.sub(repl_set, line)

    if r_d := cm.get("D_with_letter"):
        ranges = r_d.get("ranges", {})
        def repl_d1(m):
            mv = RE_D_LETTER_MATCH.match(m.group(1))
            if not mv: return m.group(0)
            num, let = int(mv.group(1)), mv.group(2)
            
            if f"D{num}" in ranges and let in ranges[f"D{num}"]:
                idx = _calc_d_idx(num, let, ranges)
                if mv.group(1) == "3": fmt = r_d.get("D3B") if in_reg else r_d.get("D3B_start", r_d.get("D3B", "").replace(".", ""))
                elif mv.group(1) == "4": fmt = r_d.get("D4B") if in_reg else r_d.get("D4B_start", r_d.get("D4B", "").replace(".", ""))
                elif set_flg: 
                    fmt = r_d.get("set_output", r_d.get("output",""))
                    op=m.group(2).replace(" ", ""); value=m.group(3).replace('\t','');
                    return fmt.format(index=idx, val=f"{op}{value}")
                else: fmt = r_d.get("output") if in_reg else r_d.get("output_start", r_d.get("output", "").replace(".", ""))
                return fmt.format(index=idx, val=f"{m.group(2)}{m.group(3)}")
            return m.group(0)
        line = RE_D_LETTER_1.sub(repl_d1, line)

        def repl_d2(m):
            mv = RE_D_LETTER_MATCH.match(m.group(3))
            if not mv: return m.group(0)
            num, let = int(mv.group(1)), mv.group(2)
            if f"D{num}" in ranges and let in ranges[f"D{num}"]:
                idx = _calc_d_idx(num, let, ranges)
                dot = "." if in_reg else ""
                fmt = r_d.get("output_val", "{content} {val}") 
                if "X" in m.group(1): return fmt.format(content=m.group(1), val=f"{m.group(2)}{dot}XD{idx}", index=idx)
                elif "Y" in m.group(1): return fmt.format(content=m.group(1), val=f"{m.group(2)}{dot}YD{idx}", index=idx)
                else: return fmt.format(content=m.group(1), val=f"{m.group(2)}{dot}YD{idx}" if mv.group(1) == "4" else f"{m.group(2)}{dot}XD{idx}", index=idx)
            return m.group(0)
        line = RE_D_LETTER_2.sub(repl_d2, line)

    if r_d := cm.get("D5n"):
        def repl_d5n_lho(m):
            mv = RE_D5N_MATCH.match(m.group(1))
            if not mv: return m.group(0)
            let = m.group(1)[2]
            idx = 11 if let == "B" else 12 if let == "C" else 13
            op=m.group(2).replace("\t", " ")
            hex_val = m.group(3).replace("$", "")
            hex = hex_val.zfill(8)
            fmt = r_d.get("output") if in_reg else r_d.get("output_start", r_d.get("output", "").replace(".", ""))
            return fmt.format(index=idx, hval=f"{op}${hex[:4]}", lval=f"{op}${hex[4:]}")
        line = RE_D5N.sub(repl_d5n_lho, line)

        def repl_d5n_rho(m):
            target = m.group(1) 
            let = target[2]
            idx = 11 if let == "B" else 12 if let == "C" else 13
            
            lhs = line.split('=')[0] if '=' in line else line
            dot = "." if in_reg else ""
            prefix = f"{dot}TD{idx}"
            
            return prefix
        line = RE_D5N_RHO.sub(repl_d5n_rho, line)

    def repl_d5(m):
        hex_val=m.group(2)
        if hex_val:
            hex = hex_val.zfill(8)
            return f"THD9=${hex[:4]} TLD9=${hex[4:]}"
        elif in_reg:
            return f".TD9"
        else:
            return f"TD9"
    line = RE_EXC_D5.sub(repl_d5, line)
    
    def repl_tp_group(m):
        tp_str = m.group(1)
        hex_val = m.group(2)
        if tp_str in ["TP","TP1"]:
            base = "TA"
            high = "THA"
            low = "TLA"
        elif tp_str in ["TP2","TP1_2","TP2_2"]:
            base = "TB"
            high = "THB"
            low = "TLB"
        else:
            base = tp_str

        if hex_val:
            hex_h, hex_l = _split_hex(hex_val)[0], _split_hex(hex_val)[1]
            return f"{high}=${hex_h} {low}=${hex_l}"
        else:
            return base
    line = RE_TP_GROUP.sub(repl_tp_group, line) 
    
    def repl_tph_group(m):
        tph_str = m.group(1)
        hex_val = m.group(2)
        is_sub2 = "_2" in tph_str
        core_str = tph_str.replace("_2","")

        if core_str =="TPH":
            b, e_val = 1,1
        else:
            b = int(core_str[3])
            e_str = core_str[4]
            e_val = {"A":1, "B":2, "C":3, "D":4}[e_str]

        base_idx = (b-1) * 4 + e_val
        idx = base_idx + 14 if is_sub2 else base_idx

        if hex_val:
            hex_h, hex_l = _split_hex(hex_val)[0], _split_hex(hex_val)[1]
            return f" THD{idx}=${hex_h} TLD{idx}=${hex_l}"
        else:
            return f"TD{idx}"
    line = RE_TPH_GROUP.sub(repl_tph_group, line)
    
    def repl_xt(m):
        xt_str = m.group(1)
        idx = m.group(2)
        val = m.group(3)
        if xt_str == "XT": idx = 1
        if val is None: return f"XT{idx}"
        return f"XT{idx}=${val}"
    line = RE_XT.sub(repl_xt, line)
    
    for key in ["IDX", "IDXI", "STI", "XSK", "YSK"]:
        if (rule := cm.get(key)) and "compiled_pattern" in rule:
            if key == "IDX":
                line = rule["compiled_pattern"].sub(lambda m: rule["output"].format(num=m.group(1).replace("IDX", ""), val=m.group(2) + m.group(3)), line)
            elif key == "IDXI":
                line = rule["compiled_pattern"].sub(lambda m: rule["output"].format(val=m.group(2), tab=""), line)
            elif key == "STI":
                line = rule["compiled_pattern"].sub(lambda m: rule["output"].format(word="NOOP", tab="\t", num=m.group(1).replace("STI", "LD").replace("\t","")+"=", val=m.group(2).replace("\t","")), line)
            else:
                line = rule["compiled_pattern"].sub(lambda m: rule["output"].format(val="".join(g for g in m.groups() if g)), line)
                
    for k in ["DRE", "CPE"]:
        if k in cm:
            for var, rule in cm[k].items():
                if "compiled_pattern" in rule:
                    line = rule["compiled_pattern"].sub(rf"\g<1>\g<2>{rule['output']}", line)
    import re


    return line

def _process_complex_commands(line, cm):
    skip_keys = {"JNI", "JSI", "JL", "SET", "D_with_letter", "D5n", "IDX", "IDXI", "STI", "XSK", "YSK", "DRE", "CPE", "TP_SPLIT", "GROUP_B_COMPILED", "GROUP_B_RULES"}
    _list = lambda v: v if isinstance(v, list) else [v] if v else [] 

    for k, rules in cm.items():
        if k in skip_keys: continue 
        rules = _list(rules)
        if not rules: continue
        
        if isinstance(rules[0], dict) and isinstance(rules[0].get("pattern"), str) and "output" in rules[0]:
            for r in rules:
                if "compiled_pattern" in r:
                    line = r["compiled_pattern"].sub(lambda m, f=r["output"]: f.format(num=m.group(1)) if "{num}" in f and m.lastindex else f, line)

    if "GROUP_B_COMPILED" in cm:
        def rep_cmd(m):
            k, num, suf = m.group(1), m.group(2), m.group(3)
            rules = cm["GROUP_B_RULES"][k]
            for r in rules:
                exts = r.get("extra")
                exts_list = exts if isinstance(exts, list) else [exts] if exts else []
                exts_clean = [e.strip() for e in exts_list if e]
                if (suf in exts_clean) if suf else ("" in exts_clean if exts_clean else True):
                    out = []
                    for p in r["pattern"]:
                        if p in ["JL", "LD", "JSL"]: out.append(f"{p}{num}")
                        else: out.append(p)
                    return "".join(out)
            return m.group(0) 
        line = cm["GROUP_B_COMPILED"].sub(rep_cmd, line)

    return line

def transform_word(w, sm, cm, in_reg=False):
    if not w or w == ".": return ""
    
    if w.startswith("$"): return w
    
    def _replace(match):
        core = match.group(0) 
        
        if core in sm: return sm[core]

        dot = "." if in_reg else ""

        if core.startswith("NH"): return f"{dot}XD14"
        if core.startswith("BH"): return f"{dot}YD14"
        
        if m := RE_PARTS.match(core):
            b, n, s = m.groups()
            if b == "N" and not s: return f"G3B{n}"
            if b == "B" and not s: return f"G4B{n}"
            
            if b in ("ND", "BD"):
                val = 14 + int(n)
                rule = cm.get(b, {})
                fmt = rule.get("output") if in_reg else rule.get("output_start", f"XD{val}{s} YD{val}{s}")
                return fmt.format(val=val, suffix=s)
                
            if b in ("NH", "BH"):
                val = int(n) 
                rule = cm.get(b, {})
                fmt = rule.get("output") if in_reg else rule.get("output_start", f"{b}{val}{s}")
                return fmt.format(val=val, suffix=s)
                
            if b in sm and not s: return f"{sm[b]}{n}"
        
        if m := RE_TPH.match(core):
            b, e = int(m.group(1)), {"A":1,"B":2,"C":3,"D":4}[m.group(2)]
            return f"TD{e if b == 1 else (b-1)*10+e}"
            
        if m := RE_D5.match(core):
            return f"XD9{m.group(1)}${m.group(2)}"

        return sm.get(core, core)

    return RE_WORD.sub(_replace, w)

def transform(text, sm, cm, psr=False, is_exception=False):
    in_reg = False 
    res = []
    
    for line in text.splitlines():
        code_part = line.split(";", 1)[0]
        if not is_exception:
            if "DATA 0" in code_part: in_reg = True
            if "TREFRESH" in code_part: in_reg = False
            if "START" in code_part: in_reg = False
            if "STPS" in code_part: in_reg = False
            if any(word in line for word in ["TSVDEC1", "TSVDEC2", "TSVEXT1", "TSVECT2", "SF_RP", "PR_", ]) and "SF" in line:
                line = line.replace("SF", "")
        else:
            in_reg = False
            
        if ";" in line:
            bef, aft = line.split(";", 1)
            aft = "/*;" + aft
        else:
            bef, aft = line, ""
        
        parts = []
        for p in RE_TAGS.split(bef):
            if RE_TAGS.match(p): parts.append(p)
            elif p: 
                p = p.replace("#", "$")
                p = p.replace('"', '^')
                p = p.replace("'", "|") 
                p = p.replace("/", "~")
                p = RE_SWAP.sub(r'\1\2=\3 \3\2=\1', p)
                p = p.replace('<', '=')
                p = _process_complex_commands(_process_regex_rules(p, cm, in_reg), cm)
                
                for k, v in sm.items():
                    if " " in k or "-" in k: p = p.replace(k, v)
                    
                out_tokens = []
                for t in RE_SPACE.split(p):
                    if t.isspace(): out_tokens.append(t) 
                    elif m := RE_C.match(t.strip()):
                        out_tokens.append(_convert_c_token(int(m.group(1)), psr))
                    elif m := RE_CYP.match(t.strip()):
                        ps_num = int(m.group(1))
                        out_tokens.append(f"APS{ps_num} BPS{ps_num + 16} CPS{ps_num}" if psr else f"APS{ps_num} BPS{ps_num} CPS{ps_num}")
                    elif m := RE_TS.match(t.strip()):
                        out_tokens.append(f"SPL{int(m.group(1))-1}")
                    elif m := RE_OP.search(t):
                        lp, rp = t[:m.start()], t[m.end():]
                        out_tokens.append(f"{transform_word(lp, sm, cm, in_reg)}{m.group(1)}{transform_word(rp, sm, cm, in_reg)}")
                    else:
                        out_tokens.append(transform_word(t, sm, cm, in_reg))
                
                parts.append("".join(out_tokens))
                
        res.append("".join(parts) + aft)

    return "\n".join(res)

def process_single_file(filename, input_dir, output_dir, use_psr, sm, cm):
    input_path = os.path.join(input_dir, filename)
    is_ext = "macrodef" in filename 
    
    with open(input_path, "r", encoding="utf-8") as f: 
        text = f.read()
    
    if is_ext:
        final = transform(text, sm, cm, psr=use_psr, is_exception=True)
        
        out_filename = os.path.splitext(filename)[0] + ".asc" 
        out_path = os.path.join(output_dir, out_filename)
        
        final = "\n".join(line.rstrip() for line in final.splitlines()) + "\n"
        with open(out_path, "w", encoding="utf-8") as f: 
            f.write(final)
            
        os.chmod(out_path, 0o777) 
        return f" [MACRO] {filename} -> {out_path}"
        
    else:
        final = transform(preprocess(text), sm, cm, psr=use_psr)
        
        out_filename = os.path.splitext(filename)[0] + ".pat"
        out_path = os.path.join(output_dir, out_filename)
        
        final = "\n".join(line.rstrip() for line in final.splitlines()) + "\n"
        with open(out_path, "w", encoding="utf-8") as f: 
            f.write(final)
            
        return f" [OK] {filename} -> {out_path}"

def main(input_dir, output_dir, use_psr):
    sm, cm = load_rules()

    if not os.path.isdir(input_dir):
        return print(f"Error: Input directory '{input_dir}' not found. 경로를 확인해주세요.")
        
    os.makedirs(output_dir, exist_ok=True)
    asc_files = [f for f in os.listdir(input_dir) if f.lower().endswith(".asc")]
    
    if not asc_files: return print(f"Info: No .asc files found in '{input_dir}'.")
        
    print(f"Found {len(asc_files)} file(s). Starting Ultra-fast Multi-core conversion...\n" + "-"*40)
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [executor.submit(process_single_file, filename, input_dir, output_dir, use_psr, sm, cm) for filename in asc_files]
        for future in concurrent.futures.as_completed(futures):
            try: print(future.result())
            except Exception as e: print(f" [ERROR] 변환 중 오류 발생: {e}")
        
    print("-" * 40 + "\nAll files have been successfully converted!")

if __name__ == "__main__":
    INPUT_DIR = "./pattern" 
    OUTPUT_DIR = "./converted_files"
    parser = argparse.ArgumentParser(description="Batch convert .asc files to .pat")
    parser.add_argument("-psr", action="store_true", help="Enable PSR mode")
    args = parser.parse_args()
    main(INPUT_DIR, OUTPUT_DIR, args.psr)
