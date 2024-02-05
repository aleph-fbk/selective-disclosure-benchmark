from pathlib import Path
from tomlkit import load

class Algorithm:

    def __init__(self, name, provider, set_path, data_path):
    
        self.name = name
        self.provider = provider
        
    
        with open(f'{set_path}/{name.lower()}.toml') as f:
            S = load(f)
            
            self.color = f"#{S['family']['color']}"
            self.color2 = f"#{S['family']['color2']}"
            
            self.marker = f"{S['family']['marker']}"
            
            _set = [s for s in S['set'].values() if s['security_level']<=2][0]

            self.set_name = _set['name']
            s_data_path = data_path / f'benches/{provider}_benchmark/target/criterion/'
            s_folder_name = f'''{provider} {name}'''
            
            self.data_path = s_data_path
            self.folder_name = s_folder_name
            
            if 'public_key_bytes' in _set.keys():
                self.public_key_bytes = _set['public_key_bytes']
            else:
                self.public_key_bytes = False
                
            if 'signature_bytes' in _set.keys():
                self.signature_bytes = _set['signature_bytes']
