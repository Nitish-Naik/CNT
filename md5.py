import hashlib


def compute_md5(input_data):
    
    md5_hash = hashlib.md5()
    
    
    md5_hash.update(input_data)
    

    return md5_hash.hexdigest()


if __name__ == "__main__":
    input_data = b"Hello, world!"
    hash_result = compute_md5(input_data)
    print("MD5:", hash_result)
