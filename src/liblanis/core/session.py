import platform
import threading
import urllib.parse

import httpx
from liblanis.core.types import AccountType
from liblanis.core.crypt import Crypt
from selectolax.lexbor import LexborHTMLParser as Parser

from .. import __version__, __isDev__


class PreventLogout(threading.Thread):
    def __init__(self, request: httpx.Client, token: str, interval: float) -> None:
        threading.Thread.__init__(self)

        self.event = threading.Event()

        self.request = request
        self.token = token
        self.interval = interval

    def run(self) -> None:
        while True:
            self.event.wait(self.interval)

            if self.event.is_set():
                break

            self.request.post(
                url=f"https://start.schulportal.hessen.de/ajax_login.php",
                data={"name": urllib.parse.quote(self.token)},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "x-requested-with": "XMLHttpRequest",
                },
            )

    def stop(self) -> None:
        self.event.set()


class Session:
    request: httpx.Client
    "A http client to make requests. Can be also used externally."

    crypt: Crypt
    "A module to decrypt encrypted sensitive data like attendance."

    token = ""
    "The token of the current session. Resembles the 'sid' cookie."

    account_type: AccountType
    "The account type of the current session. Currently only student accounts are supported."

    user_data: dict
    "The user data of the current session in a dict. Mostly basic personal data."

    _prevent_logout_interval = 10.0
    _prevent_logout: PreventLogout


    def __init__(self, school_id: int, username: str, password: str) -> None:
        self.school_id = school_id
        self.username = username
        self.password = password

        self._authenticate()

    def deauthenticate(self) -> None:
        self._prevent_logout.stop()

        self.request.get(url="https://start.schulportal.hessen.de/index.php?logout=all")

        self.request.close()

    def _authenticate(self) -> None:
        self.request = self._get_request_client()

        credentials_handshake = self.request.post(
            url=f"https://login.schulportal.hessen.de/",
            params={"i": self.school_id},
            data={"user": f"{self.school_id}.{self.username}", "user2": self.username, "password": self.password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        login_url = self.request.head(url=f"https://connect.schulportal.hessen.de", )

        start_session = self.request.head(login_url.headers.get("location"))

        self.token = start_session.cookies.get("sid")

        self.crypt = Crypt(self.request)

        self._prevent_logout = PreventLogout(self.request, self.token, self._prevent_logout_interval)
        self._prevent_logout.start()

        account_data_response = self.request.get(
            "https://start.schulportal.hessen.de/benutzerverwaltung.php?a=userData")
        account_data_page = Parser(account_data_response.content)

        self._parse_account_type(account_data_page)
        self._parse_user_data(account_data_page)

    def _get_request_client(self) -> httpx.Client:
        return httpx.Client(
            http2=True,
            headers={
                "User-Agent": f"liblanis/v{__version__} for python on {platform.system()} ({'dev' if __isDev__ else 'release'})"},
            timeout=8.0,
            event_hooks={"response": [self._decrypt_response]}
        )

    def _decrypt_response(self, response: httpx.Response) -> None:
        content = response.read()

        if content:
            content_type = response.headers.get("content-type")
            if 'text/html' in content_type:
                decrypted_content = self.crypt.decrypt_encoded_tags(content.decode())
                response._content = decrypted_content

    def _parse_account_type(self, account_data_page: Parser) -> None:
        icon_class_list = account_data_page.css_first(".nav.navbar-nav.navbar-right>li>a>i").attributes.get("class")
        if "fa-child" in icon_class_list:
            self.account_type = AccountType.STUDENT
        elif "fa-user-circle" in icon_class_list:
            self.account_type = AccountType.PARENT
        elif "fa-user" in icon_class_list:
            self.account_type = AccountType.TEACHER

    def _parse_user_data(self, account_data_page: Parser) -> None:
        user_data_table_body = account_data_page.css_first("div.col-md-12 table.table.table-striped tbody")

        if user_data_table_body.html is not None:
            result = {}

            rows = user_data_table_body.css("tr")
            for row in rows:
                childs = row.iter()

                key = next(childs).text(strip=True)
                value = next(childs).text(strip=True)

                key = key.lower()

                result[key] = value

            self.user_data = result

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.deauthenticate()
