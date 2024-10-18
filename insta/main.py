import requests
from lxml import html
import re
import sys
import pprint
import json
from profilepic import pp_download

def banner():
    print('\t""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""')
    print('\t                         Instagram Profile Data Grabber                    ')
    print('\t""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""')

def main(username):
    banner()
    '''Main function accepts Instagram username
    and returns a dictionary object containing profile details
    '''

    url = f"https://www.instagram.com/{username}/?hl=en"
    page = requests.get(url)

    # Store page content to a file for debugging
    try:
        with open("nitish.txt", "w", encoding='utf-8') as file:
            file.write(page.text)
    except Exception as e:
        print(f"Error writing to file: {e}")

    tree = html.fromstring(page.content)
    account_type = None  # Initialize account type
    is_private = None  # Initialize privacy status
    profile_description = None  # Initialize profile description

    # Find the script tag containing account type and privacy information
    scripts = tree.xpath('//script[contains(text(), "window.__additionalData__")]/text()')
    if scripts:
        json_text = re.search(r'window\.__additionalData__\s*=\s*(\{.*\});', scripts[0])
        if json_text:
            json_data = json.loads(json_text.group(1))
            user_data = json_data.get('graphql', {}).get('user', {})
            if user_data:
                is_private = user_data.get('is_private', False)
                account_type = "Business" if user_data.get('is_verified', False) else "Personal"

    # Extract the profile description from the og:description meta tag
    profile_description_meta = tree.xpath('//meta[@property="og:description"]/@content')
    if profile_description_meta:
        profile_description = profile_description_meta[0]

    # Extract other profile details
    data = tree.xpath('//meta[starts-with(@name,"description")]/@content')
    if data:
        data = data[0].split(', ')
        followers = data[0][:-9].strip()
        following = data[1][:-9].strip()
        posts = re.findall(r'\d+[,]*', data[2])[0]
        name = re.findall(r'name":"([^"]+)"', page.text)[0]

        instagram_profile = {
            'success': True,
            'profile': {
                'name': name,
                'profileurl': url,
                'username': username,
                'followers': followers,
                'following': following,
                'posts': posts,
                'account_type': account_type,  # Include account type
                'is_private': is_private,  # Include privacy status
                'description': profile_description  # Include profile description
            }
        }
    else:
        instagram_profile = {
            'success': False,
            'profile': {}
        }
    
    return instagram_profile

#  python main.py username
if __name__ == "__main__":
    if len(sys.argv) == 2:
        output = main(sys.argv[-1])
        pp_download(sys.argv[-1])  # Assuming this function exists for downloading profile pictures
        pprint.pprint(output)
    else:
        print('Invalid parameters. Valid Command: \n\tUsage: python main.py username')
