def reformat_address(addr, group, ch):
    addr = str(addr)
    return ch.join(addr[i:i+group] for i in range(0, len(addr), group))

def reformat_ipv4(addr):
    output = ''
    for ch in addr:
        output += str(int(ch)) + '.'
    return output[:-1]

def bytes_to_ascii(data):
    output = 'ascii<'
    for i in range(len(data)):
        if int(data[i])<128:
            output += chr(data[i])
        else:
            output += ' '
    output += '>'
    return output