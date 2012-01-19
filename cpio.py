#!/usr/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301, USA

# Copyright 2011 Andrew Holmes <andrew.g.r.holmes@gmail.com>

"""
The CPIO file format is a common UNIX archive standard which collects file
system objects into a single stream of bytes.  This module provides tools to
create, read and write CPIO archives.

This module currently supports the formats described by the following
constants:

.. autodata:: NEW_MAGIC
.. autodata:: CRC_MAGIC
.. autodata:: OLD_MAGIC
.. autodata:: BIN_MAGIC

The :mod:`cpio` module provides reasonably fine-grained error handling via the
following exceptions:

.. autoexception:: Error
.. autoexception:: HeaderError
.. autoexception:: ChecksumError
.. autoexception:: FormatError

Application Protocol Interface
------------------------------

.. autoclass:: CpioFile
    :members:
.. autoclass:: CpioEntry
    :members:

Command Line Interface
----------------------

Some stuff

Examples
--------

Some simple examples
"""

# psyco JIT compiler support
try:
    import psyco
    psyco.full()
except:
    pass

import io
import os
import os.path
import stat
import struct


__all__ = [
    'is_cpioarchive',
    'CpioFile',
    'CpioEntry',
    'Error',
    'HeaderError',
    'ChecksumError',
    'FormatError',
    'NEW_MAGIC']

NEW_MAGIC = '070701'
"""*undocumented*"""
CRC_MAGIC = '070702'
"""*undocumented*"""
OLD_MAGIC = '070707'
"""*undocumented*"""
BIN_MAGIC = 070707
"""*undocumented*"""

NEW_STRUCT = '=6s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s 8s'
OLD_STRUCT = '=6s 6s 6s 6s 6s 6s 6s 6s 11s 6s 11s'
BIN_STRUCT = 'H H H H H H H H 2H H 2H'


def is_cpioarchive(self, path):
    """Quickly check the magic number of a file."""
    with io.open(path, 'rb') as fileobj:
        buf = fileobj.read(6)

        if buf in (NEW_MAGIC, CRC_MAGIC, OLD_MAGIC):
            return True
        if struct.unpack('<H', buf[:2])[0] == BIN_MAGIC:
            return True
        if struct.unpack('>H', buf[:2])[0] == BIN_MAGIC:
            return True

    return False


def checksum32(bytes):
    """Return a 32-bit unsigned sum of *bytes*."""
    return sum(ord(byte) for byte in bytes) & 0xFFFFFFFF


class Error(Exception):
    """Base class for cpio exceptions"""
    pass


class HeaderError(Error):
    """
    The base class for header errors.  Both :exc:`ChecksumError` and
    :exc:`FormatError` inherit from this exception.
    """
    pass


class ChecksumError(HeaderError):
    """Raised when a checksum of an member's data doesn't match its header."""
    pass


class FormatError(HeaderError):
    """
    This may be raised by CpioEntry when an unsupported format is encountered
    or by CpioFile if an unexpected format change is detected mid-archive.
    """
    pass


class CpioEntry(object):
    """
    CpioEntry provides a unified set of attributes to represent different cpio
    formats.  If the member is a regular file it will supports :meth:`read()`,
    :meth:`seek()` and :meth:`tell()` operations; if it is a symbolic link the
    target will be available as :attr:`target`.

    .. note::
        The :mod:`stat` module provides functions to test for specific file
        types that may be performed on the :attr:`mode` attribute.
    """

    __slots__ = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'mtime', 'rdev',
                 'size', 'check', 'target', 'name', 'fileobj', 'filepos',
                 'position']

    def __init__(self, fileobj):
        """
        *fileobj* may be any binary mode file object which supports read(),
        write() and seek() methods.
        """
        self.fileobj = fileobj
        self.filepos = None
        self.position = 0

        self.dev = 0
        """Number of the device the inode resides on."""
        self.ino = 0
        """Inode number on disk."""
        self.mode = 0
        """Inode protection mode."""
        self.uid = 0
        """User id of the owner."""
        self.gid = 0
        """Group id of the owner."""
        self.nlink = 0
        """Number of links to the inode."""
        self.mtime = 0
        """Time of last modification."""
        self.rdev = 0
        """Number of the device type."""
        self.size = 0
        """Size of the file data in bytes."""
        self.check = None
        """32-bit checksum of the file data (New CRC format only)."""
        self.target = None
        """The target path (symbolic links only)."""
        self.name = 'TRAILER!!!'
        """Pathname of the member."""

    def __eq__(self, other):
        """
        Members are considered equal if they point to the same inode and
        device numbers (eg. hardlinks).
        """
        return (isinstance(other, self.__class__)
                and self.ino == other.ino
                and self.dev == other.dev)

    def from_fileobj(self):
        """*undocumented*"""
        buf = self.fileobj.read(6)

        if buf in (NEW_MAGIC, CRC_MAGIC):
            hdr = struct.unpack(NEW_STRUCT, buf + self.fileobj.read(104))
        elif buf == OLD_MAGIC:
            hdr = struct.unpack(OLD_STRUCT, buf + self.fileobj.read(70))
        # using the magic number to determine endianness
        elif struct.unpack('<H', buf[:2])[0] == BIN_MAGIC:
            hdr = struct.unpack('<' + BIN_STRUCT, buf + self.fileobj.read(20))
        elif struct.unpack('>H', buf[:2])[0] == BIN_MAGIC:
            hdr = struct.unpack('>' + BIN_STRUCT, buf + self.fileobj.read(20))
        else:
            raise HeaderError('unknown or unsupported format')

        if hdr[0] in (NEW_MAGIC, CRC_MAGIC):
            #self.magic = hdr[0]
            self.ino = int(hdr[1], 16)
            self.mode = int(hdr[2], 16)
            self.uid = int(hdr[3], 16)
            self.gid = int(hdr[4], 16)
            self.nlink = int(hdr[5], 16)
            self.mtime = int(hdr[6], 16)
            self.size = int(hdr[7], 16)
            self.dev = os.makedev(int(hdr[8], 16), int(hdr[9], 16))
            self.rdev = os.makedev(int(hdr[10], 16), int(hdr[11], 16))
            namesize = int(hdr[12], 16)
            self.check = int(hdr[13], 16)

            hpad = (4 - (110 + namesize) % 4) % 4
            dpad = (4 - self.size % 4) % 4
        elif hdr[0] == OLD_MAGIC:
            #self.magic = hdr[0]
            self.dev = int(hdr[1], 8)
            self.ino = int(hdr[2], 8)
            self.mode = int(hdr[3], 8)
            self.uid = int(hdr[4], 8)
            self.gid = int(hdr[5], 8)
            self.nlink = int(hdr[6], 8)
            self.rdev = int(hdr[7], 8)
            self.mtime = int(hdr[8], 8)
            namesize = int(hdr[9], 8)
            self.size = int(hdr[10], 8)

            hpad, dpad = 0, 0
        elif hdr[0] == BIN_MAGIC:
            #self.magic = hdr[0]
            self.dev = hdr[1]
            self.ino = hdr[2]
            self.mode = hdr[3]
            self.uid = hdr[4]
            self.gid = hdr[5]
            self.nlink = hdr[6]
            self.rdev = hdr[7]
            # one big-endian long in two bi-endian shorts
            self.mtime = hdr[8] * 256**2 + hdr[9]
            namesize = hdr[10]
            self.size = hdr[11] * 256**2 + hdr[12]

            hpad = (2 - (26 + namesize) % 2) % 2
            dpad = (2 - self.size % 2) % 2

        # Read the member name; exclude the trailing NUL byte and padding
        self.name = self.fileobj.read(namesize + hpad)[:namesize - 1]

        # set the data offset, read through the data and checksum if CRC
        if stat.S_ISREG(self.mode):
            self.filepos = self.fileobj.tell()
            data = self.fileobj.read(self.size + dpad)[:self.size]

            if hdr[0] == CRC_MAGIC and self.check != checksum32(data):
                raise ChecksumError(self.name)
        elif stat.S_ISLNK(self.mode):
            self.target = self.fileobj.read(self.size + dpad)[:self.size]

    def to_fileobj(self, format, data=None):
        """Write the member in *format*."""
        if format in (NEW_MAGIC, CRC_MAGIC):
            hpad = (4 - (111 + len(self.name)) % 4) % 4
            dpad = (4 - self.size % 4) % 4

            self.fileobj.write(
                ''.join([
                    format,
                    '{:0>8x}'.format(self.ino),
                    '{:0>8x}'.format(self.mode),
                    '{:0>8x}'.format(self.uid),
                    '{:0>8x}'.format(self.gid),
                    '{:0>8x}'.format(self.nlink),
                    '{:0>8x}'.format(self.mtime),
                    '{:0>8x}'.format(self.size),
                    '{:0>8x}'.format(os.major(self.dev)),
                    '{:0>8x}'.format(os.minor(self.dev)),
                    '{:0>8x}'.format(os.major(self.rdev)),
                    '{:0>8x}'.format(os.minor(self.rdev)),
                    '{:0>8x}'.format(len(self.name) + 1),
                    '{:0>8x}'.format(self.check),
                    self.name, '\0',
                    ''.rjust(hpad, '\0')]))
        elif format == OLD_MAGIC:
            hpad, dpad = 0, 0

            self.fileobj.write(
                ''.join([
                    format,
                    '{:0>6o}'.format(self.dev),
                    '{:0>6o}'.format(self.ino),
                    '{:0>6o}'.format(self.mode),
                    '{:0>6o}'.format(self.uid),
                    '{:0>6o}'.format(self.gid),
                    '{:0>6o}'.format(self.nlink),
                    '{:0>6o}'.format(self.rdev),
                    '{:0>11o}'.format(self.mtime),
                    '{:0>6o}'.format(len(self.name) + 1),
                    '{:0>11o}'.format(self.size),
                    self.name, '\0']))
        elif format == BIN_MAGIC:
            hpad = (2 - (27 + len(self.name)) % 2) % 2
            dpad = (2 - self.size % 2) % 2

            self.fileobj.write(
                ''.join([
                    struct.pack(
                        BIN_STRUCT,
                        format,
                        self.dev,
                        self.ino,
                        self.mode,
                        self.uid,
                        self.gid,
                        self.nlink,
                        self.rdev,
                        self.mtime / 256**2,
                        self.mtime % 256**2,
                        len(self.name) + 1,
                        self.size / 256**2,
                        self.size % 256**2),
                    self.name, '\0',
                    ''.rjust(hpad, '\0')]))

        if data:
            self.filepos = self.fileobj.tell()
            self.fileobj.write(data + ''.rjust(dpad, '\0'))

    def read(self, n=-1):
        """Read *n* bytes from the member.

        .. note::
           :exc:`io.UnsupportedOperation` will be raised if the member is not
           a regular file.
        """
        if not stat.S_ISREG(self.mode):
            raise io.UnsupportedOperation('not a file FIXME')

        # seek to current object position, if not already there
        if self.fileobj.tell() != self.filepos + self.position:
            self.fileobj.seek(self.filepos + self.position)

        # return '' if at EOF for this object
        if self.fileobj.tell() == self.filepos + self.size:
            return ''

        #
        if n < 0 or n >= (self.size - self.position):
            data = self.fileobj.read(self.size - self.position)
        else:
            data = self.fileobj.read(n)

        self.position += len(data)

        return data

    def seek(self, offset, whence=io.SEEK_SET):
        """
        Change the stream position to the given byte *offset*, relative to the
        position indicated by *whence* and return the absolute position. See
        :meth:`~io.IOBase.seek` in the :mod:`io` module.

        .. note::
           :exc:`io.UnsupportedOperation` will be raised if the member is not
           a regular file.
        """
        if not stat.S_ISREG(self.mode):
            raise io.UnsupportedOperation('not a file FIXME')

        if whence == io.SEEK_SET:
            self.position = offset
        elif whence == io.SEEK_CUR:
            self.position += offset
        elif whence == io.SEEK_END:
            self.position -= offset

        self.position = min(max(0, self.position), self.size)

        return self.position

    def tell(self):
        """Return the current stream position.

        .. note::
           :exc:`io.UnsupportedOperation` will be raised if the member is not
           a regular file.
        """
        if not stat.S_ISREG(self.mode):
            raise io.UnsupportedOperation('not a file FIXME')

        return self.position


class CpioFile(object):
    """
    CpioFile is a file-like object that acts as a container of CpioEntry
    objects, which in turn allow access to the attributes and data.
    """

    def __init__(self, path=None, mode='rb', fileobj=None, format=None):
        """
        The new class instance is based on *fileobj*, which may be any binary
        mode file object which supports read(), write() and seek() methods.
        If *fileobj* is None then *path* will be used to provide a file
        object.

        The *mode* argument must be either 'rb' or 'wb'.  The default is 'rb'
        either if *path* is given or if *fileobj* is read-write.

        The *format* argument should be one of :const:`NEW_MAGIC`,
        :const:`CRC_MAGIC`, :const:`OLD_MAGIC` or :const:`BIN_MAGIC`.
        """
        if not path and not fileobj:
            raise ValueError('either fileobj or path must be given')

        if mode not in('rb', 'wb'):
            raise ValueError('mode must be either "rb" or "wb".')

        self._members = []
        self.fileobj = fileobj or io.open(path, mode)
        self.format = format
        """*undocumented*"""

        # If the file object is readable and a known format, read it
        if self.fileobj.readable():
            member = CpioEntry(self.fileobj)
            member.from_fileobj()

            while member.name != 'TRAILER!!!':
                if member.name != '.':
                    self._members.append(member)

                member = CpioEntry(self.fileobj)
                member.from_fileobj()

            if self.format in (NEW_MAGIC, CRC_MAGIC):
                self._fix_hardlinks()

    def __enter__(self):
        return self

    def __exit__(self, extype, exvalue, extraceback):
        if extype is None:
            return self.close()

    def __iter__(self):
        return iter(self._members)

    def __repr__(self):
        s = repr(self.fileobj)
        return '<cpio ' + s[1:-1] + ' ' + hex(id(self)) + '>'

    def _fix_hardlinks(self):
        """Amend the file metrics of hardlink members."""
        islink = lambda e: e.nlink > 1 and not stat.S_ISDIR(e.mode)
        hasdata = lambda e: islink(e) and e.size > 0

        for inode in [member for member in self if hasdata(member)]:
            for link in [member for member in self if not hasdata(member)]:
                if link.ino == inode.ino and link.dev == inode.dev:
                    link.filepos = inode.filepos
                    link.size = inode.size
                    link.nlink = 1

    def add(self):
        """*undocumented*"""
        pass

    def addfile(self):
        """*undocumented*"""
        pass

    #FIXME
    def close(self):
        """
        Close the :class:`CpioFile`. In write-mode, a trailer is appended to
        the archive.
        """
        if self.fileobj is None:
            return

        #if self.fileobj.writable():
        #    self._write_member(CpioEntry(self.fileobj))

        self.flush()
        self.fileobj = None

    def closed(self):
        """True if the stream is closed."""
        return self.fileobj is None

    def extract(self, member, path='.'):
        """Extract an member from the archive.

        The *member* argument should be the member's pathname or a CpioEntry
        object.

        The *path* argument is a path to a directory, defaulting to the
        current working directory, where the file will be extracted.

        .. warning::
           Never extract archives from untrusted sources without prior
           inspection. It is possible that files are created outside of path,
           e.g. members that have absolute filenames starting with "/" or
           filenames with two dots "..".
        """
        # get CpioEntry by *name*
        if not isinstance(member, CpioEntry):
            for candidate in self:
                if candidate.name == member:
                    member = candidate

        path = os.path.join(path, member.name)

        # Create a file on disk for the appropriate type
        if stat.S_ISDIR(member.mode):
            os.mkdir(path, member.mode & 0777)
        elif stat.S_ISREG(member.mode):
            with io.open(path, 'wb') as pathobj:
                member.seek(0)
                pathobj.write(member.read())
        #FIXME: unix only
        elif os.name == 'posix':
            if stat.S_ISLNK(member.mode):
                os.symlink(member.target, path)
            else:
                os.mknod(path, member.mode, member.dev)

    def extractall(self, path=None):
        """Extract all members from the archive to the current working
        directory or directory path.

        .. warning::
           See the warning for :meth:`extract`.
        """
        for member in self:
            self.extract(member, path)

    def extractfile(self, member):
        """*undocumented*"""
        pass

    def fileno(self):
        """Invoke the underlying file object's fileno() method."""
        return self.fileobj.fileno()

    #FIXME
    def flush(self):
        """Write a trailer member, if writable(), and flush the file-object"""
        self.fileobj.flush()

    def namelist(self):
        """Return a list of member names."""
        return [member.name for member in self]

    def readable(self):
        return self.fileobj.readable()

    #FIXME
    def write(self, path, **kwargs):
        """*undocumented*"""
        member = CpioEntry(self.fileobj)
        pstat = os.lstat(path)

        member.dev = pstat.st_dev
        member.ino = pstat.st_ino
        member.mode = pstat.st_mode
        member.uid = pstat.st_uid
        member.gid = pstat.st_gid
        member.nlink = pstat.st_nlink
        member.mtime = pstat.st_mtime
        member.size = pstat.st_size
        member.name = path

        # not available on non-linux systems
        if hasattr(pstat, 'st_rdev'):
            member.rdev = pstat.st_rdev

        # FIXME: update member attributes with kwargs
        for key in [key for key in kwargs.keys() if hasattr(member, key)]:
            member.__dict__[key] = kwargs[key]

        # write the data; regular files and symbolic links only
        if stat.S_ISREG(self.mode):
            with io.open(path, 'rb') as pathobj:
                # compute the `check` header field, if applicable
                if self.format == CRC_MAGIC:
                    data = pathobj.read()
                    member.check = checksum32(data)
                    self._write_member(member, data)
                else:
                    self._write_member(member, pathobj.read())
        # The target of a symbolic link is stored as file data
        elif stat.S_IFLNK(self.mode):
            self._write_member(member, os.readlink(path))

        self._members.append(member)


#FIXME: command line interface

def main():
    """*undocumented*"""
    with CpioFile('test.bin.cpio') as cpio:
        #cpio.extractall('test')
        print cpio.namelist()


if __name__ == "__main__":
    main()
