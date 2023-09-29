import requests
requests.packages.urllib3.disable_warnings()

class API:
    def __init__(self,key,base_url,proxies : dict = {}, verify_ssl : bool = False):
        self.session = requests.Session()
        self.base_url = base_url
        self.key=key
        self.session.proxies = proxies
        self.session.verify = verify_ssl
    
    def __results(self,method, path, payload):
        full_url = self.base_url + path
        return self.session.request(method, full_url, payload)
    
    def start_image(self, imageName):
        method = 'GET'
        path = '/path/here'
        payload = {}
        return self.__results(method, path, payload)

