from typing import BinaryIO, Optional
from cherrypy.lib.httputil import HeaderElement

class Entity:
    content_type: Optional[HeaderElement] = None
    filename: Optional[str] = None

class Part(Entity):
    file: Optional[BinaryIO] = None
