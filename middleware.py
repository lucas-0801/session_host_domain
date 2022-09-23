import re
import time

from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import SuspiciousOperation
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date


class SessionHostDomainMiddleware(SessionMiddleware):
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_SAVE_EVERY_REQUEST = False
    SESSION_COOKIE_NAME = 'sessionid'
    SESSION_COOKIE_PATH = '/'
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_DOMAIN = '.example.com'
    SESSION_COOKIE_DOMAIN_DICT = {
        '.example.com': r'[a-zA-Z0-9\-_.:]*.example.com',
        '.domain.com': r'[a-zA-Z0-9\-_.:]*.example.com'
    }

    def process_response(self, request, response):
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError:
            pass
        else:
            host = request.get_host()
            domain = self.SESSION_COOKIE_DOMAIN

            for key, pattern in self.SESSION_COOKIE_DOMAIN_DICT.items():
                if re.compile(pattern).match(host):
                    domain = key
                    break

            if self.SESSION_COOKIE_NAME in request.COOKIES and empty:
                response.delete_cookie(
                    key=self.SESSION_COOKIE_NAME,
                    path=self.SESSION_COOKIE_PATH,
                    domain=domain,
                    samesite=self.SESSION_COOKIE_SAMESITE,
                )
            else:
                if accessed:
                    patch_vary_headers(response, ('Cookie',))
                if (modified or self.SESSION_SAVE_EVERY_REQUEST) and not empty:
                    if request.session.get_expire_at_browser_close():
                        max_age = None
                        expires = None
                    else:
                        max_age = request.session.get_expiry_age()
                        expires_time = time.time() + max_age
                        expires = http_date(expires_time)

                    # Save the session data and refresh the client cookie.
                    # Skip session save for 500 responses, refs #3881.
                    if response.status_code != 500:
                        try:
                            request.session.save()
                        except UpdateError:
                            raise SuspiciousOperation(
                                "The request's session was deleted before the "
                                "request completed. The user may have logged "
                                "out in a concurrent request, for example."
                            )

                        response.set_cookie(
                            self.SESSION_COOKIE_NAME,
                            request.session.session_key, max_age=max_age,
                            expires=expires, domain=domain,
                            path=self.SESSION_COOKIE_PATH,
                            secure=self.SESSION_COOKIE_SECURE or None,
                            httponly=self.SESSION_COOKIE_HTTPONLY or None,
                            samesite=self.SESSION_COOKIE_SAMESITE,
                        )
        return response
