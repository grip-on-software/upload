from types import TracebackType
from typing import Callable, IO, Optional, Tuple, Type, TypeVar, Union
from . import gpgme as gpgme

_Hook = TypeVar('_Hook', bound=Optional[Callable])
_ReadCB = Callable[[int, _Hook], bytes]
_WriteCB = Callable[[bytes, _Hook], int]
_SeekCB = Callable[[int, int, _Hook], int]
_ReleaseCB = Callable[[_Hook], None]

class GpgmeWrapper:
    def __getattr__(self, key: str) -> Optional[Union[bool, Callable]]: ...

class Data(GpgmeWrapper):
    def __init__(self,
                 string: Optional[str] = None,
                 file: Optional[Union[str, IO]] = None,
                 offset: Optional[int] = None,
                 length: Optional[int] = None,
                 cbs: Optional[
                     Union[Tuple[_ReadCB, _WriteCB, _SeekCB, _ReleaseCB],
                           Tuple[_ReadCB, _WriteCB, _SeekCB, _ReleaseCB, _Hook]]
                 ] = None,
                 copy: bool = True): ...
    def __enter__(self) -> 'Data': ...
    def __exit__(self, type: Optional[Type[BaseException]],
                 value: Optional[BaseException],
                 tb: Optional[TracebackType]) -> None: ...
    def write(self, buffer: Union[str, bytes]) -> int: ...
    def read(self, size: int = -1) -> Union[str, bytes]: ...
