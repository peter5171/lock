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
RE_X_OUT = re.compile(r'\b(X)\b(\s*[<=]+\s*)(XT)(\d+)')

RE_D_ASSIGN = re.compile(r'\b(D\d*[A-Z]?(?:_2)?)\s*([<+=])\s*([#$][A-Fa-f0-9_]+)\b')
RE_TP_ASSIGN = re.compile(r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?)\s*([<+=])\s*(.*?)(?=\s+\b[A-Za-z0-9_]+\s*[<+=]|$)')
RE_EQUATION = re.compile(r'\b([A-Za-z0-9_]+)\s*([<+=])\s*(.*?)(?=\s+\b[A-Za-z0-9_]+\s*[<+=]|$)')

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
# ==============================================================================
# 💡 [1단계] XCS / YCS 완벽 분할 매크로
# ==============================================================================
def _process_cs_macros(line):
    
    def repl_cs(m):
        lhs = m.group(1)
        op = m.group(2)
        rhs = m.group(3).strip()
        
        if 'XCS' not in lhs and 'XCS' not in rhs and 'YCS' not in lhs and 'YCS' not in rhs:
            return m.group(0)
            
        equations = [(lhs, rhs)]
        
        if 'XCS' in lhs or 'XCS' in rhs:
            new_eqs = []
            for l, r in equations:
                new_eqs.append((re.sub(r'\bXCS\b', 'XC', l), re.sub(r'\bXCS\b', 'XC', r)))
                new_eqs.append((re.sub(r'\bXCS\b', 'XS', l), re.sub(r'\bXCS\b', 'XS', r)))
            equations = new_eqs
            
        if 'YCS' in lhs or 'YCS' in rhs:
            new_eqs = []
            for l, r in equations:
                new_eqs.append((re.sub(r'\bYCS\b', 'YC', l), re.sub(r'\bYCS\b', 'YC', r)))
                new_eqs.append((re.sub(r'\bYCS\b', 'YS', l), re.sub(r'\bYCS\b', 'YS', r)))
            equations = new_eqs
            
        return " ".join([f"{l}{op}{r}" for l, r in equations])

    return RE_EQUATION.sub(repl_cs, line)


# ==============================================================================
# 💡 [2단계] D 레지스터 & TP/TPH 통합 파서 (생략 없음)
# ==============================================================================
def _process_data_register(line, cm, in_reg):
    r_d = cm.get("D_with_letter", {})
    ranges = r_d.get("ranges", {})

    # ----------------------------------------------------
    # [Pass 1] 복합 할당식 가로채기 (High/Low 분배)
    # ----------------------------------------------------
    
    # 1. TP/TPH 가로채기
# ----------------------------------------------------
    # [Pass 1] 복합 할당식 가로채기 (High/Low 분배)
    # ----------------------------------------------------
    
    # 💡 수정 1: 문장 끝까지 잡아먹지 않고, 다음 수식이 나오기 전까지만 정확히 끊어 읽는 정규식
    
    def repl_tp_assign(m):
        lhs, op, rhs = m.group(1), m.group(2), m.group(3).strip()
        out_op = '=' if op == '<' else op

        # 💡 수정 2: 비대칭 매핑의 핵심! (TP = TPH 형태는 1:1 매핑이 가능하므로 쪼개지 않음)
        # 좌변이 TP계열이고, 우변이 순수한 TPH계열 단일 토큰이라면 Pass 2(TA=TD1)로 넘깁니다.
        if lhs in ["TP", "TP1", "TP2", "TP1_2", "TP2_2"] and re.match(r'^TPH(?:[12][A-D])?(?:_2)?$', rhs):
            return m.group(0)

        # 좌변 High/Low 타겟 설정
        if lhs.startswith("TPH"):
            is_sub2 = "_2" in lhs
            core_str = lhs.replace("_2", "")
            idx = 1 if core_str == "TPH" else (int(core_str[3]) - 1) * 4 + {"A":1, "B":2, "C":3, "D":4}.get(core_str[4], 1)
            idx += 14 if is_sub2 else 0
            h_lhs, l_lhs = f"THD{idx}", f"TLD{idx}"
        else:
            h_lhs, l_lhs = ("THA", "TLA") if lhs in ["TP", "TP1"] else ("THB", "TLB")
            
        # (이하 기존 우변 시프트 및 스마트 치환 로직 동일)
        if rhs.startswith(("#", "$")):
            h, l = _split_24bit_hex(rhs)
            return f"{h_lhs}{out_op}${h} {l_lhs}{out_op}${l}"
        
        def get_hl_token(tok, is_high):
            if tok.startswith("TPH"):
                is_sub2 = "_2" in tok
                c = tok.replace("_2", "")
                i = 1 if c == "TPH" else (int(c[3]) - 1) * 4 + {"A":1, "B":2, "C":3, "D":4}.get(c[4], 1)
                i += 14 if is_sub2 else 0
                return f"THD{i}" if is_high else f"TLD{i}"
            if tok.startswith("TP"):
                return ("THA" if is_high else "TLA") if tok in ["TP", "TP1"] else ("THB" if is_high else "TLB")
            if tok == "D5": return "THD9" if is_high else "TLD9"
            if tok == "D5_2": return "THD20" if is_high else "TLD20"
            m_d5n = re.match(r"^D5([A-Z])(?:_2)?$", tok)
            if m_d5n:
                i = 11 if m_d5n.group(1) == 'B' else 12 if m_d5n.group(1) == 'C' else 13
                return f"THD{i}" if is_high else f"TLD{i}"
            return tok

        token_pattern = r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D5(?:[A-Z])?(?:_2)?)\b'
        h_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), True), rhs)
        l_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), False), rhs)
        return f"{h_lhs}{out_op}{h_rhs} {l_lhs}{out_op}{l_rhs}"

    line = RE_TP_ASSIGN.sub(repl_tp_assign, line)

    # 2. D 계열 가로채기
    def repl_d_assign(m):
        token, op, val = m.group(1), m.group(2), m.group(3)
        h, l = _split_24bit_hex(val)
        
        if token == "D5_2": return f"THD20{op}${h} TLD20{op}${l}"
        if token.startswith("D5"):
            idx = 11 if token[2]=='B' else 12 if token[2]=='C' else 13
            return f"THD{idx}{op}${h} TLD{idx}{op}${l}"
            
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", token)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            idx = _calc_d_idx(num, let, ranges) if let else num
            return f"XD{idx}{op}${h} {'YD' if num==4 else 'XD'}{idx}{op}${l}"
        return m.group(0)

    line = RE_D_ASSIGN.sub(repl_d_assign, line)

    # ----------------------------------------------------
    # [Pass 2] 단독 출현 토큰 1:1 최종 매핑
    # ----------------------------------------------------
    def repl_final_token(m):
        tok = m.group(1)
        
        # TP/TPH 계열 단독 매핑
        if tok in ["TP", "TP1"]: return "TA"
        if tok in ["TP2", "TP1_2", "TP2_2"]: return "TB"
        if tok.startswith("TPH"):
            is_sub2 = "_2" in tok
            core_str = tok.replace("_2", "")
            if core_str == "TPH": return "TD1"
            else:
                b = int(core_str[3])
                e_val = {"A":1, "B":2, "C":3, "D":4}.get(core_str[4], 1)
                idx = (b-1) * 4 + e_val
                idx += 14 if is_sub2 else 0
                return f"TD{idx}"
                
        # D5 계열 단독 매핑
        if tok == "D5_2": return "TD20"
        if tok == "D5": return "TD9"
        m_d5n = re.match(r"^D5([A-Z])(?:_2)?$", tok)
        if m_d5n:
            idx = 11 if m_d5n.group(1) == 'B' else 12 if m_d5n.group(1) == 'C' else 13
            return f"TD{idx}"
            
        # 나머지 D 계열 단독 매핑
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", tok)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            if f"D{num}" in ranges and (not let or let in ranges[f"D{num}"]):
                idx = _calc_d_idx(num, let, ranges) if let else num
                prefix = "YD" if num == 4 else "XD"
                suffix = "_2" if "_2" in tok else ""
                return f"{prefix}{idx}{suffix}"
                
        return tok

    line = re.sub(r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D\d*[A-Z]?(?:_2)?)\b', repl_final_token, line)
    
    return line
	
def repl_xt(m):
    xt_str = m.group(1)
    idx = m.group(2)
    val = m.group(3)
    if xt_str == "XT": idx = 1
    if val is None: return f"XT{idx}"
	return f"XT{idx}=${val}"
	
def repl_x_out(m):
	num = m.group(4)
	return f"XT{num}"

# ==============================================================================
# 🚀 [메인 실행 함수]
# ==============================================================================
def _process_regex_rules(line, cm, in_reg=False):
	
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
		
	line = re.sub(r'\b([A-Za-z0-9_]+)\s*<>\s*([A-Za-z0-9_]+)\b', r'\1=\2 \2=\1', line)	
	
    # 1. 수식 격리 및 XCS / YCS 분할
    line = _process_cs_macros(line)

    # 2. TP / TPH / D 계열 완벽 처리 (High/Low 및 단독 치환)
    line = _process_data_register(line, cm, in_reg)

    # 3. 기타 장비 규칙 치환 (기존 시스템 유지)
    # 이미 1,2단계에서 완벽히 치환했으므로 꼬이지 않도록 이 키들은 무시합니다.
    skip_keys = ["D_with_letter", "D5n", "XCS", "YCS", "TP_GROUP", "TPH_GROUP"]
    
    for key, rule in cm.items():
        if key in skip_keys:
            continue
            
        # 사용하시던 나머지 기본 룰셋 처리 로직
        if "compiled_pattern" in rule:
            if "output" in rule:
                # 일반적인 단순 정규식 치환
                line = rule["compiled_pattern"].sub(rule["output"], line)
            
    # XT변환 규칙
    line = RE_XT.sub(repl_xt, line)
    
	# X<XT 대응
	line = RE_X_OUT.sub(repl_x_out, line)
	
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
