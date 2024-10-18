import requests
from lxml import html
import re
import sys

def main(username):
    '''main function accepts Instagram username
    returns a dictionary object containing profile details
    '''
    url = f"https://www.instagram.com/{username}/?hl=en"
    page = requests.get(url)

    if page.status_code != 200:
        return {'success': False, 'error': 'Profile not found or private.'}

    tree = html.fromstring(page.content)
    data = tree.xpath('//meta[starts-with(@name,"description")]/@content')

    if data:
        data = data[0].split(', ')
        
        if len(data) < 3:
            return {'success': False, 'error': 'Unexpected format in profile data.'}
        
        followers = data[0][:-9].strip()
        following = data[1][:-9].strip()
        posts_match = re.findall(r'\d+', data[2])
        
        if not posts_match:
            posts = "0"
        else:
            posts = posts_match[0]
        
        name_match = re.findall(r'name":"([^"]+)"', page.text)
        name = name_match[-1] if name_match else "N/A"
        
        aboutinfo_match = re.findall(r'"description":"([^"]+)"', page.text)
        aboutinfo = aboutinfo_match[0] if aboutinfo_match else "N/A"
        
        instagram_profile = {
            'success': True,
            'profile': {
                'name': name,
                'profileurl': url,
                'username': username,
                'followers': followers,
                'following': following,
                'posts': posts,
                'aboutinfo': aboutinfo
            }
        }
    else:
        instagram_profile = {
            'success': False,
            'profile': {}
        }
    
    return instagram_profile

# python InstagramProfile.py username
if __name__ == "__main__":
    '''driver code'''
    if len(sys.argv) == 2:
        output = main(sys.argv[-1])
        print(output)
    else:
        print('=========>Invalid parameters. Valid command is<=========== \
        \npython InstagramProfile.py username')
