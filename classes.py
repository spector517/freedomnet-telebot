from time import sleep
from requests import get


class Build():

    __slots__ = ('cid', 'job_url', 'build_params', 'auth', 'url', 'status', 'artifacts')

    def __init__(self, cid: str, job_url: str, build_params: dict, auth: tuple) -> None:
        self.cid = cid
        self.job_url = job_url
        self.build_params = build_params
        self.auth = auth
        self.__create_build()
        # Jenkins pending
        sleep(10)
        self.update()

    def __eq__(self, other_build: object) -> bool:
        return self.cid == other_build.cid

    def __ne__(self, other_build: object) -> bool:
        return not self.__eq__(other_build)

    def __hash__(self) -> int:
        hash(f'{type(self)}_{self.cid}')


    def __create_build(self) -> None:
        # Get next build number
        job_info_response = get(f'{self.job_url}/api/json', auth=self.auth)
        if job_info_response.status_code != 200:
            raise Exception(f'Error: get job info {self.job_url} return incorrect' +
                f' status code: {job_info_response.status_code}')
        next_build_number: int = job_info_response.json()['nextBuildNumber']

        # Build job with parameters
        build_create_response = get(f'{self.job_url}/buildWithParameters',
            params=self.build_params, auth=self.auth)
        if build_create_response.status_code != 201:
            raise Exception(f'Error: create build {self.job_url} return incorrect' +
                f' status code: {build_create_response.status_code}')

        # Set url and status
        self.url = f'{self.job_url}/{next_build_number}'
        self.status = 'in_progress'


    def update(self) -> None:
        build_info_response = get(f'{self.url}/api/json', auth=self.auth)
        if build_info_response.status_code != 200:
            raise Exception(f'Error: get job info {self.url} return incorrect' +
                f' status code: {build_info_response.status_code}')
        build_info = build_info_response.json()

        self.artifacts = [artifact['relativePath'] for artifact in build_info['artifacts']]
        if build_info['inProgress']:
            self.status = 'in_progress'
        elif build_info['result'] == 'SUCCESS':
            self.status = 'success'
        elif build_info['result'] == 'UNSTABLE':
            self.status = 'unstable'
        elif build_info['result'] == 'FAILURE':
            self.status = 'fail'


    def get_artifacts(self) -> dict:
        files = {}
        for artifact in self.artifacts:
            artifact_response = get(f'{self.url}/artifact/{artifact}', auth=self.auth)
            files.update({artifact: artifact_response.content})
            if artifact_response.status_code != 200:
                raise Exception(f'Error: download artifact {artifact} of job {self.url}' +
                    f'return incorrect status code {artifact_response.status_code}')
        return files


class Client:

    __slots__ = ('cid', 'build', 'lang', 'host', 'user', 'password')

    def __init__(self, cid: int, build: Build = None, lang: str = 'ru',
            host: str = None, user: str = None, password: str = None) -> None:
        self.cid = cid
        self.build = build
        self.lang = lang
        self.host = host
        self.user = user
        self.password = password
    
    def __eq__(self, other_client: object) -> bool:
        return self.cid == other_client.cid

    def __ne__(self, other_client: object) -> bool:
        return not self.__eq__(other_client)

    def __hash__(self) -> int:
        return hash(f'{type(self)}_{self.cid}')


class VpnClient(Client):

    __slots__ = ('cid', 'build', 'lang', 'host', 'user', 'password', 'vpn_clients')

    def __init__(self, cid: int, build: Build = None, lang: str = 'ru', 
            host: str = None, user: str = None, password: str = None, vpn_clients: list = []) -> None:
        super().__init__(cid, build, lang, host, user, password)
        self.vpn_clients = vpn_clients
