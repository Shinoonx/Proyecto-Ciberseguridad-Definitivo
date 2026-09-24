import os
import requests
from typing import List, Dict

def get_repositories(org_name: str) -> List[Dict]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("La variable de entorno GITHUB_TOKEN no está definida.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    repos = []
    url = f"https://api.github.com/orgs/{org_name}/repos"
    
    while url:
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            raise Exception(f"Error de la API de GitHub: {response.status_code} - {response.text}")
            
        data = response.json()
        for repo in data:
            repos.append({
                "name": repo.get("name"),
                "url": repo.get("html_url"),
                "clone_url": repo.get("clone_url"),
                "language": repo.get("language")
            })
        
        # GitHub envía la URL de la siguiente página en el header 'Link'
        url = response.links.get("next", {}).get("url")
        
    return repos