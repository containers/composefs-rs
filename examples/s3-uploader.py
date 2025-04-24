import argparse
import errno
import os
import threading
import concurrent.futures
from collections.abc import Iterator
from typing import Any

import boto3
from botocore.exceptions import ClientError
import magic
import zstd


class MimeDB(threading.local):
    db: magic.Magic

    def getdb(self) -> magic.Magic:
        if not hasattr(self, "db"):
            db = magic.open(magic.MAGIC_MIME | magic.MAGIC_MIME_ENCODING)
            assert db is not None
            result = db.load()
            assert result == 0
            self.db = db

        return self.db

    def content_type_for_data(self, data: bytes) -> str:
        result = self.getdb().buffer(data)
        assert result is not None
        result = result.replace("; charset=binary", "")  # this is just silly...
        return result


mimedb = MimeDB()


def ensure_file(bucket: Any, dirfd: int, path: str) -> None:
    obj = bucket and bucket.Object(path)

    if obj is not None:
        try:
            # This is a HEAD request only
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/object/load.html
            obj.load()
            print(f"{path}: skip")
            return  # done!
        except ClientError as e:
            if e.response["Error"]["Code"] != "404":
                raise

    try:
        with open(os.open(path, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd), "rb") as f:
            data = f.read()

        content_type = mimedb.content_type_for_data(data)
    except OSError as exc:
        if exc.errno != errno.ELOOP:
            raise

        data = os.readlink(path, dir_fd=dirfd).encode('utf-8', 'surrogateescape')
        content_type = 'text/x-symlink-target'

    # 22 is max but RFC 9659 limits the window size to 8MB, which we get at level 19
    # we could possibly tweak other parameters to be more aggressive...
    compressed = zstd.compress(data, 19)

    # skip compression unless it made a meaningful difference
    ratio = len(data) / len(compressed)  # len(compressed) won't be 0
    if ratio > 1.1:
        print(
            f"{path}: {content_type} zstd {len(data)} → {len(compressed)} ({ratio:.2f}x compression)"
        )
        content_encoding = "zstd"
        data = compressed
    else:
        print(f"{path}: {content_type} as-is {len(data)} ({ratio:.2f}x)")
        content_encoding = ""

    if obj is not None:
        obj.put(Body=data, ContentEncoding=content_encoding, ContentType=content_type)


def find_not_type_d(dir_fd: int) -> Iterator[str]:
    for dirpath, _dirnames, filenames, _dirfd in os.fwalk(dir_fd=dir_fd):
        yield from (os.path.normpath(os.path.join(dirpath, name)) for name in filenames)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="https://nbg1.your-objectstorage.com")
    parser.add_argument("--bucket", default="lis")
    parser.add_argument("-j", "--jobs", type=int, default=64)
    parser.add_argument("dir")

    args = parser.parse_args()

    # https://github.com/boto/boto3/issues/4392
    # https://docs.hetzner.com/storage/object-storage/getting-started/using-s3-api-tools/
    os.environ["AWS_REQUEST_CHECKSUM_CALCULATION"] = "WHEN_REQUIRED"

    dirfd = os.open(args.dir, os.O_PATH | os.O_CLOEXEC)
    files = sorted(find_not_type_d(dirfd))
    print(f"Found {len(files)} files to process.")

    s3: Any = boto3.resource("s3", endpoint_url=args.endpoint)
    bucket = s3.Bucket(args.bucket)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        for _ in executor.map(lambda file: ensure_file(bucket, dirfd, file), files):
            pass


if __name__ == "__main__":
    main()
