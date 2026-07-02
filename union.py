
def _process_master_registers(line, cm, in_reg):
    split_flg = 1 
    
    # [추가된 부분] 쪼갤 대상을 한정하는 허용 목록
    SPLIT_ALLOWED_PREFIXES = ("TPH", "D5")

    

        if lhs in ["TP", "TP1", "TP2", "TP1_2", "TP2_2"] and re.match(r'^TPH(?:[12][A-D])?(?:_2)?$', rhs):
            return m.group(0)

        # [변경된 부분] #, $ 외에 숫자 시작도 인정하고, 허용 목록에 없으면 튕겨냄
        is_hex_value = bool(re.match(r'^[#$0-9]', rhs))
        
        if is_hex_value and not lhs.startswith(SPLIT_ALLOWED_PREFIXES):
            return m.group(0)

        if split_flg == 1:

            
# [변경된 부분] 정규식 끝에 순수 숫자도 잡도록 추가됨 
    RE_D_ASSIGN = re.compile(r'\b(D\d*[A-Z]?(?:_2)?)\s*([<+=])\s*([#$][A-Fa-f0-9_]+|[0-9][A-Fa-f0-9_]*)\b', re.IGNORECASE)
    
    def repl_d_assign(m):
        token, op, val = m.group(1), m.group(2), m.group(3)
        
        # [추가된 부분] 허용 목록 방어 
        if not token.startswith(SPLIT_ALLOWED_PREFIXES):
            return m.group(0)
            
        h, l = _split_24bit_hex(val)

      

    RE_D_ASSIGN = re.compile(r'\b(D\d*[A-Z]?(?:_2)?)\s*([<+=])\s*([#$][A-Fa-f0-9_]+|[0-9][A-Fa-f0-9_]*)\b', re.IGNORECASE)
    def repl_d_assign(m):
        token, op, val = m.group(1), m.group(2), m.group(3)
        
        # 🚨 [방어 로직] 허용 목록에 없는 D 계열(예: D1A)은 쪼개지 않고 Pass 2로 넘김!
        if not token.startswith(SPLIT_ALLOWED_PREFIXES):
            return m.group(0)
            
        h, l = _split_24bit_hex(val)
        #[out of range 수정] 
        if token == "D5": return f"{dot}THD9{op}${h} {dot}TLD9{op}${l}"
        if token == "D5_2": return f"{dot}THD20{op}${h} {dot}TLD20{op}${l}"
        if token.startswith("D5"):
            # 여기까지 왔다면 D5A, D5B 처럼 무조건 3글자 이상임이 보장됨
            idx = 11 if token[2]=='B' else 12 if token[2]=='C' else 13
            return f"{dot}THD{idx}{op}${h} {dot}TLD{idx}{op}${l}"
        #[수정 끝]    


        # (만약 나중에 D1 등을 허용 목록에 추가했을 때를 대비한 기본 로직 유지)
        m_let = re.match(r"^D(\d*)([A-Z]?)(?:_2)?$", token)
        if m_let:
            num = int(m_let.group(1) or 0)
            let = m_let.group(2)
            idx = _calc_d_idx(num, let, ranges) if let else num
            return f"{dot}XD{idx}{op}${h} {dot}{'YD' if num==4 else 'XD'}{idx}{op}${l}"
        return m.group(0)

    line = RE_D_ASSIGN.sub(repl_d_assign, line)



import traceback # (맨 위에 추가) 에러의 상세 원인을 추적하기 위한 기본 모듈

def main():
    # 💡 1. 에러를 차곡차곡 모아둘 빈 리스트를 준비합니다.
    error_log = []

    # (파일을 읽어오거나 텍스트를 가져오는 기존 코드)
    # with open('input.txt', 'r') as f:
    #     lines = f.readlines()

    # 💡 2. enumerate에 start=1을 주어서 1번째 줄부터 번호를 셉니다.
    for line_num, line in enumerate(lines, start=1):
        try:
            # 기존에 하시던 정상적인 처리 로직
            # in_reg 플래그 등의 처리는 질문자님의 기존 코드 흐름대로 유지하세요.
            processed_line = _process_regex_rules(line, cm, in_reg)
            
            # 정상적으로 변환되었으면 원래대로 print
            print(processed_line, end="") 
            
        except Exception as e:
            # 🚨 [에러 발생!] 프로그램이 멈추지 않게 낚아채서 error_log에 기록합니다.
            error_msg = f"Line {line_num} ➔ 에러 원인: {str(e)}\n  (원본 문장: {line.strip()})"
            error_log.append(error_msg)
            
            # 출력물이 망가지지 않도록 에러가 난 줄은 원본을 그냥 출력하거나 
            # 주석 처리해서 출력해줍니다. (선택 사항)
            print(f"; [ERROR_SKIPPED] {line}", end="") 


    # =====================================================================
    # 💡 3. 모든 출력이 끝난 맨 밑바닥에서 에러 리스트를 쫙 뿌려줍니다.
    # =====================================================================
    if error_log:
        print("\n\n" + "="*60)
        print("🚨 🚨 🚨 [경고] 변환 중 발생한 오류 리스트 🚨 🚨 🚨")
        print("="*60)
        for err in error_log:
            print(err)
            print("-" * 60)
        print("총 {}개의 라인에서 오류가 발생했습니다.".format(len(error_log)))
        print("="*60)

# 실행
# if __name__ == "__main__":
#     main()

