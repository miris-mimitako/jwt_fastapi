import random
import string


class RandomString:
    def __init__(self) -> None:
        pass
    
    def normal_random_text(self, length:int) -> str:
        if length < 1:
            raise "Error: 1以上の数値を指定してください。"
        else:
            pass
        
        dat = string.digits + string.ascii_lowercase + string.ascii_uppercase
        return ''.join([random.choice(dat) for i in range(length)])

    def lowercase_random_text(self, length:int)->str:
        if length < 1:
            raise "Error: 1以上の数値を指定してください。"
        else:
            pass
        
        dat = string.digits + string.ascii_lowercase
        return ''.join([random.choice(dat) for i in range(length)])
    
if __name__=="__main__":
    RS = RandomString()
    print(RS.lowercase_random_text(64))