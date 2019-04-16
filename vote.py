try:
    import requests
except Exception ImportError:
    print('requests is not installed installing it!')
    import os
    os.system('python -m pip install requests')

def main():
    username = ""
    password = ""
    params = {
        'username' : username
        'password' : password
    }
    url = ""
    #r = requests.post()

main()
