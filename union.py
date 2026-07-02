import re

def _process_master_registers(line, cm, in_reg):
    # ==========================================
    # 💡 1. 쪼개기 모드 설정 플래그 (0: 전체 분리, 1: 조건부 분리)
    split_flg = 1 
    
    # 💡 2. 16진수 값을 High/Low로 쪼갤 좌변(LHS) "허용 접두사 목록"
    # 나중에 TP, D1 등 추가가 필요하면 이 괄호 안에 "TP", "D1" 식으로 추가만 하시면 됩니다!
    # (.startswith 로 검사하므로 "D5"만 적어도 D5, D5_2, D5A 모두 자동 적용됩니다)
    SPLIT_ALLOWED_PREFIXES = ("TPH", "D5")
    # ==========================================
    
    dot = "." if in_reg else "" 

    r_d = cm.get("D_with_letter", {})
    ranges = r_d.get("ranges", {})

    # ----------------------------------------------------
    # [Pass 1] 복합 할당식 가로채기 (High/Low 분배)
    # ----------------------------------------------------
    
    # 1. TP/TPH 가로채기
    RE_TP_ASSIGN = re.compile(r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?)\s*([<+=])\s*(.*?)(?=\s+\b[A-Za-z0-9_]+\s*[<+=]|$)')
    
    def repl_tp_assign(m):
        lhs, op, rhs = m.group(1), m.group(2), m.group(3).strip()
        out_op = '=' if op == '<' else op

        # [예외] TA=TD1 1:1 통과
        if lhs in ["TP", "TP1", "TP2", "TP1_2", "TP2_2"] and re.match(r'^TPH(?:[12][A-D])?(?:_2)?$', rhs):
            return m.group(0)

        # 우변이 16진수(기호 포함 또는 순수 숫자)인지 확인
        is_hex_value = bool(re.match(r'^[#$0-9]', rhs))
        
        # 🚨 [방어 로직] 16진수 값인데, 허용 목록(TPH, D5 등)에 없는 좌변이라면 쪼개지 않음!
        if is_hex_value and not lhs.startswith(SPLIT_ALLOWED_PREFIXES):
            return m.group(0)

        # [조건부 분리 (모드 1)]
        if split_flg == 1:
            is_invalid_format = lhs.startswith("TPH") and rhs in ["TP", "TP1", "TP2", "TP1_2", "TP2_2"]
            if not is_hex_value and not is_invalid_format:
                return m.group(0)

        # 좌변 High/Low 타겟 설정
        if lhs.startswith("TPH"):
            is_sub2 = "_2" in lhs
            core_str = lhs.replace("_2", "")
            idx = 1 if core_str == "TPH" else (int(core_str[3]) - 1) * 4 + {"A":1, "B":2, "C":3, "D":4}.get(core_str[4], 1)
            idx += 14 if is_sub2 else 0
            h_lhs, l_lhs = f"{dot}THD{idx}", f"{dot}TLD{idx}"
        else:
            h_lhs, l_lhs = (f"{dot}THA", f"{dot}TLA") if lhs in ["TP", "TP1"] else (f"{dot}THB", f"{dot}TLB")
            
        # 우변 시프트 분할
        if is_hex_value:
            m_hex = re.match(r'^([#$][A-Fa-f0-9_]+|[0-9][A-Fa-f0-9_]*)(.*)$', rhs, re.IGNORECASE)
            if m_hex:
                hex_val = m_hex.group(1)
                trailing_junk = m_hex.group(2)
                h, l = _split_24bit_hex(hex_val)
                return f"{h_lhs}{out_op}${h} {l_lhs}{out_op}${l}{trailing_junk}"
        
        # 우변 스마트 치환 (수식 분할)
        def get_hl_token(tok, is_high):
            if tok.startswith("TPH"):
                is_sub2 = "_2" in tok
                c = tok.replace("_2", "")
                i = 1 if c == "TPH" else (int(c[3]) - 1) * 4 + {"A":1, "B":2, "C":3, "D":4}.get(c[4], 1)
                i += 14 if is_sub2 else 0
                return f"{dot}THD{i}" if is_high else f"{dot}TLD{i}"
            if tok.startswith("TP"):
                return (f"{dot}THA" if is_high else f"{dot}TLA") if tok in ["TP", "TP1"] else (f"{dot}THB" if is_high else f"{dot}TLB")
            if tok == "D5": return f"{dot}THD9" if is_high else f"{dot}TLD9"
            if tok == "D5_2": return f"{dot}THD20" if is_high else f"{dot}TLD20"
            m_d5n = re.match(r"^D5([A-Z])(?:_2)?$", tok)
            if m_d5n:
                i = 11 if m_d5n.group(1) == 'B' else 12 if m_d5n.group(1) == 'C' else 13
                return f"{dot}THD{i}" if is_high else f"{dot}TLD{i}"
            return f"{dot}{tok}" if tok in ["D1A", "D2A", "XCS"] else tok

        token_pattern = r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D5(?:[A-Z])?(?:_2)?)\b'
        h_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), True), rhs)
        l_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), False), rhs)
        return f"{h_lhs}{out_op}{h_rhs} {l_lhs}{out_op}{l_rhs}"

    line = RE_TP_ASSIGN.sub(repl_tp_assign, line)

    # 2. D 계열 가로채기 (16진수 할당 전용)
    RE_D_ASSIGN = re.compile(r'\b(D\d*[A-Z]?(?:_2)?)\s*([<+=])\s*([#$][A-Fa-f0-9_]+|[0-9][A-Fa-f0-9_]*)\b', re.IGNORECASE)
    def repl_d_assign(m):
        token, op, val = m.group(1), m.group(2), m.group(3)
        
        # 🚨 [방어 로직] 허용 목록에 없는 D 계열(예: D1A)은 쪼개지 않고 Pass 2로 넘김!
        if not token.startswith(SPLIT_ALLOWED_PREFIXES):
            return m.group(0)
            
        h, l = _split_24bit_hex(val)
        
        if token == "D5_2": return f"{dot}THD20{op}${h} {dot}TLD20{op}${l}"
        if token.startswith("D5"):
            idx = 11 if token[2]=='B' else 12 if token[2]=='C' else 13
            return f"{dot}THD{idx}{op}${h} {dot}TLD{idx}{op}${l}"
            
        # (만약 나중에 D1 등을 허용 목록에 추가했을 때를 대비한 기본 로직 유지)
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", token)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            idx = _calc_d_idx(num, let, ranges) if let else num
            return f"{dot}XD{idx}{op}${h} {dot}{'YD' if num==4 else 'XD'}{idx}{op}${l}"
        return m.group(0)

    line = RE_D_ASSIGN.sub(repl_d_assign, line)

    # ----------------------------------------------------
    # [Pass 2] 단독 출현 토큰 1:1 최종 매핑
    # ----------------------------------------------------
    def repl_final_token(m):
        tok = m.group(1)
        
        if tok in ["TP", "TP1"]: return f"{dot}TA"
        if tok in ["TP2", "TP1_2", "TP2_2"]: return f"{dot}TB"
        if tok.startswith("TPH"):
            is_sub2 = "_2" in tok
            core_str = tok.replace("_2", "")
            if core_str == "TPH": return f"{dot}TD1"
            else:
                b = int(core_str[3])
                e_val = {"A":1, "B":2, "C":3, "D":4}.get(core_str[4], 1)
                idx = (b-1) * 4 + e_val
                idx += 14 if is_sub2 else 0
                return f"{dot}TD{idx}"
                
        if tok == "D5_2": return f"{dot}TD20"
        if tok == "D5": return f"{dot}TD9"
        m_d5n = re.match(r"^D5([A-Z])(?:_2)?$", tok)
        if m_d5n:
            idx = 11 if m_d5n.group(1) == 'B' else 12 if m_d5n.group(1) == 'C' else 13
            return f"{dot}TD{idx}"
            
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", tok)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            if f"D{num}" in ranges and (not let or let in ranges[f"D{num}"]):
                idx = _calc_d_idx(num, let, ranges) if let else num
                
                # 💡 [복구됨] 문맥 인식(X/Y) 스마트 스캐너
                if re.search(r'\bY\s*[<+=]', line):
                    prefix = "YD"
                elif re.search(r'\bX\s*[<+=]', line):
                    prefix = "XD"
                else:
                    prefix = "YD" if num == 4 else "XD"
                    
                suffix = "_2" if "_2" in tok else ""
                return f"{dot}{prefix}{idx}{suffix}"
                
        return tok

    line = re.sub(r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D\d*[A-Z]?(?:_2)?)\b', repl_final_token, line)
    
    return line
