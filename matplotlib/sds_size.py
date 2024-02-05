

# map selective disclosure signatures to public key sizes

def public_key(set_name: str, number_of_attributes: int):
    
    if set_name == 'CL':
    
        n = 3072//8
        return (3+number_of_attributes)*n
    
    elif set_name == 'BBS+':
        
        # with setup parameters:
        # 2*96+48*(1+number_of_attributes)
    
        return 96 
        
    elif set_name == 'BBS':

        # with setup parameters:
        # 2*96+48*(1+number_of_attributes)
        
        return 96

    elif set_name == 'PS':

        return 96+48*(2+number_of_attributes)

    else:
    
        print('SDS not available')
        return 0


# map selective disclosure signatures to disclosure sizes

def disclosure(set_name: str, number_of_attributes: int, number_of_disclosed_attributes: int):
    
    na = number_of_attributes
    nd = number_of_disclosed_attributes
    digest_size = 32
    
    if set_name == 'CL':
    
        n = 3072//8
        v = 3744//8 #4084//8
        return digest_size + n + 58 + v + 74.125*(na-nd)
    
    elif set_name == 'BBS+':
    
        return 5*48 + 32*(4+na-nd)
    
    elif set_name == 'BBS':

        return 3*48 + 32*(2+na-nd)

    elif set_name == 'PS':

        return 2*96 + 2*48 + 32*(1+na-nd)

    else:
    
        print('SDS not available')
        return 0
