def reformat_address(addr, group, ch):
    addr = str(addr)
    return ch.join(addr[i:i+group] for i in range(0, len(addr), group))
