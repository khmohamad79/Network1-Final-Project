def reformat_address(addr, group, ch):
    str = str(str)
    return ch.join(addr[i:i+group] for i in range(0, len(addr), group))
