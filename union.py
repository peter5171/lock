
    # ----------------------------------------------------
    # [Pass 2] 단독 출현 토큰 1:1 최종 매핑
    # ----------------------------------------------------
    def repl_final_token(m):
        tok = m.group(1)
        
        # (TP / TPH 계열 로직은 기존과 동일)
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
            
        # 💡 [핵심 복구] D 계열: 좌변 문맥을 스캔하여 X/Y 판단
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", tok)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            if f"D{num}" in ranges and (not let or let in ranges[f"D{num}"]):
                idx = _calc_d_idx(num, let, ranges) if let else num
                
                # 🚀 문장 전체(line)를 스캔해서 좌변에 Y가 있는지, X가 있는지 확인!
                if re.search(r'\bY\s*[<+=]', line):
                    prefix = "YD"
                elif re.search(r'\bX\s*[<+=]', line):
                    prefix = "XD"
                else:
                    # 좌변에 딱히 X, Y가 명시되지 않았다면 기존 규칙(num==4일때만 YD) 사용
                    prefix = "YD" if num == 4 else "XD"
                    
                suffix = "_2" if "_2" in tok else ""
                return f"{dot}{prefix}{idx}{suffix}"
                
        return tok









def _process_master_registers(line, cm, in_reg):
    # ==========================================
    # 💡 쪼개기 모드 설정 플래그 (0: 전체 분리, 1: 조건부 분리)
    # ==========================================
    split_flg = 1 
    
    # 💡 [핵심 패치] 함수 최상단에서 dot을 한 번만 정의하여 
    # Pass 1(할당식)과 Pass 2(단독식) 모두에 완벽하게 일괄 적용합니다.
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

        # [조건부 분리]
        if split_flg == 1:
            is_hex_value = rhs.startswith(("#", "$"))
            is_invalid_format = lhs.startswith("TPH") and rhs in ["TP", "TP1", "TP2", "TP1_2", "TP2_2"]
            if not is_hex_value and not is_invalid_format:
                return m.group(0)

        # 좌변 High/Low 타겟 설정 (dot 일괄 적용)
        if lhs.startswith("TPH"):
            is_sub2 = "_2" in lhs
            core_str = lhs.replace("_2", "")
            idx = 1 if core_str == "TPH" else (int(core_str[3]) - 1) * 4 + {"A":1, "B":2, "C":3, "D":4}.get(core_str[4], 1)
            idx += 14 if is_sub2 else 0
            h_lhs, l_lhs = f"{dot}THD{idx}", f"{dot}TLD{idx}"
        else:
            h_lhs, l_lhs = (f"{dot}THA", f"{dot}TLA") if lhs in ["TP", "TP1"] else (f"{dot}THB", f"{dot}TLB")
            
        # 우변 시프트 분할 (16진수 안전 파싱 및 trailing junk 보존 적용)
        if rhs.startswith(("#", "$")):
            m_hex = re.match(r'^([#$][A-Fa-f0-9_]+)(.*)$', rhs)
            if m_hex:
                hex_val = m_hex.group(1)
                trailing_junk = m_hex.group(2)
                h, l = _split_24bit_hex(hex_val)
                return f"{h_lhs}{out_op}${h} {l_lhs}{out_op}${l}{trailing_junk}"
        
        # 우변 스마트 치환 (수식 분할 시 dot 적용)
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
            return f"{dot}{tok}" if tok in ["D1A", "D2A", "XCS"] else tok # (안전장치)

        token_pattern = r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D5(?:[A-Z])?(?:_2)?)\b'
        h_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), True), rhs)
        l_rhs = re.sub(token_pattern, lambda match: get_hl_token(match.group(1), False), rhs)
        return f"{h_lhs}{out_op}{h_rhs} {l_lhs}{out_op}{l_rhs}"

    line = RE_TP_ASSIGN.sub(repl_tp_assign, line)

    # 2. D 계열 가로채기 (💡 할당식에도 dot 완벽 적용!)
    RE_D_ASSIGN = re.compile(r'\b(D\d*[A-Z]?(?:_2)?)\s*([<+=])\s*([#$][A-Fa-f0-9_]+)\b')
    def repl_d_assign(m):
        token, op, val = m.group(1), m.group(2), m.group(3)
        h, l = _split_24bit_hex(val)
        
        if token == "D5_2": return f"{dot}THD20{op}${h} {dot}TLD20{op}${l}"
        if token.startswith("D5"):
            idx = 11 if token[2]=='B' else 12 if token[2]=='C' else 13
            return f"{dot}THD{idx}{op}${h} {dot}TLD{idx}{op}${l}"
            
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", token)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            idx = _calc_d_idx(num, let, ranges) if let else num
            return f"{dot}XD{idx}{op}${h} {dot}{'YD' if num==4 else 'XD'}{idx}{op}${l}"
        return m.group(0)

    line = RE_D_ASSIGN.sub(repl_d_assign, line)

    # ----------------------------------------------------
    # [Pass 2] 단독 출현 토큰 1:1 최종 매핑 (기존 dot 로직은 외부 dot을 그대로 사용)
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
                prefix = "YD" if num == 4 else "XD"
                suffix = "_2" if "_2" in tok else ""
                return f"{dot}{prefix}{idx}{suffix}"
                
        return tok

    line = re.sub(r'\b(TPH(?:[12][A-D])?(?:_2)?|TP(?:[12]_2|[12])?|D\d*[A-Z]?(?:_2)?)\b', repl_final_token, line)
    
    return line


# IDX, STI 오류
# 4. 나머지 장비 규칙 치환
    skip_keys = ["D_with_letter", "D5n", "XCS", "YCS", "TP_GROUP", "TPH_GROUP", "SET"]
    for key, rule in cm.items():
        if key in skip_keys:
            continue
            
        if isinstance(rule, dict):
            if "compiled_pattern" in rule and "output" in rule:
                # 💡 [핵심 패치] 단순 치환이 아니라, 정규식 그룹의 이름을 가져와서 
                # {num}, {val} 자리에 값을 쏙쏙 넣어주는(format) 고급 치환 로직!
                try:
                    # 정규식 매칭 결과를 받아와서 이름표(groupdict)대로 format에 넣어줍니다.
                    line = rule["compiled_pattern"].sub(
                        lambda m: rule["output"].format(**m.groupdict()), line
                    )
                except KeyError:
                    # 만약 {} 포맷이 없는 일반 문자열이라면 기존처럼 단순 치환
                    line = rule["compiled_pattern"].sub(rule["output"], line)

# Debug
print(f"AB_ 포함 여부: {'AB_' in line}, ABCD 포함 여부: {'ABCD' in line}, 원본: {line}")
if any(word in line for word in ["XYZ1", "AB_"]) and "ABCD" in line:
    line = line.replace("ABCD", "")

#ASCDS 제거
if any(re.search(rf'\b{word}\b', line) for word in ["XYZ1", "PR_"]) and "ASCDS" in line:
    line = line.replace("ASCDS", "")

import re

import re

# 1. 트리거 확인: "XYZ1" 이나 "AB_" 가 라인에 존재하는지 확인
if any(word in line for word in [ "PR_"]):
    # 2. 제거 실행: 독립된 단어인 'SABCD' 또는 'ABCD'를 모두 찾아 빈 문자열로 제거
    line = re.sub(r'\b(SCROFF|PSCROFF)\b', '', line)
