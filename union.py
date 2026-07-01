#_process_data_register의 일부분 수정
		# 우변 시프트 분할 (값 할당)
        if rhs.startswith(("#", "$")):
            m_hex = re.match(r'^([#$][A-Fa-f0-9_]+)(.*)$', rhs)
            if m_hex:
                hex_val = m_hex.group(1)       # 순수한 16진수 값 (예: #0000000000)
                trailing_junk = m_hex.group(2) # 뒤에 남은 탭이나 문자 (예: \t\t\t XYC)
                
                h, l = _split_24bit_hex(hex_val) # 이제 순수 숫자만 들어가므로 에러 안 남!
                
                # 쪼갠 결과 뒤에 원래 있던 찌꺼기(trailing_junk)를 그대로 다시 붙여줌
                return f"{h_lhs}{out_op}${h} {l_lhs}{out_op}${l}{trailing_junk}"   
        
