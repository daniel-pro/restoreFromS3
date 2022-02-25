#!/usr/bin/env python3
'''
    File name: restoreFromS3.py
    Author: Daniel Procopio
    Creation date: 24-Jan-2022
    Last modified: 25-Feb-2022
    Python Version: 3.8
'''
import argparse
import boto3
import datetime
import errno
import logging
import os
import pytz
import time
from pathlib import Path
from rich.logging import RichHandler
from rich.tree import Tree



def valid_date(s):
    """
    Checks if the date has a valid format.
    :param s: date
    :return validated date in string format
    """

    try:
        return str(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        msg = "not a valid date: {0!r}".format(s)
        raise argparse.ArgumentTypeError(msg)

def format_bytes(size):
    """
    Calculate the size in a human readable format
    :param size: bytes
    :return value, format
    """
    # 2**10 = 1024
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'kilo', 2: 'mega', 3: 'giga', 4: 'tera'}
    while size > power:
        size /= power
        n += 1
    return size, power_labels[n]+'bytes'

def get_time_in_secs(ns):
    """
    Converts time from ns (1/1.000.000.000 or 10^-9) to s
    :param ns: nanoseconds - string provided by the AWS API
    """
    ns = ns.replace('ns','')
    try:
        secs = int(ns) / 1000000000
    except BaseException as e:
            raise
    return secs


def restore_from_s3(client, bucket, path, target, restore_date):
    """
    Downloads recursively the given S3 path to the target directory and restore files.
    :param client: S3 client to use.
    :param bucket: the name of the bucket to download from
    :param path: The S3 directory to download.
    :param target: the local directory to download the files to.
    :param restore_point_date: date to be used for restoring files that have a version date <=
    """

    log.info("")
    log.info("Restore started at {}".format(datetime.datetime.now()))
    log.info("              Parameters")
    log.info("             Bucket: {}".format(bucket))
    log.info("        Bucket Path: {}".format(path))
    log.info("         Local Path: {}".format(target))
    log.info(" Restore Point Date: {}".format(restore_point_date))
    log.info("            Logfile: {}".format(logfilename))
    log.info("")

    single_file_restore = False
    if not path.endswith('/'):
         single_file_restore = True

    total_objs = 0
    total_size = 0

    md = []
    paginator = client.get_paginator('list_objects_v2')
    for result in paginator.paginate(Bucket=bucket, Prefix=path):
        # Download each file individually
        for key in result['Contents']:
            total_objs += 1

            tgtobj = target + "/" + str(key['Key'])
            # if path ends with / is a directory
            if key['Key'].endswith('/'):
                try:
                    tree = Tree( "", guide_style="bold bright_blue")
                    log.info("Restoring dir: {} as {}".format(str(key['Key']), tgtobj))
                    os.makedirs(tgtobj)
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        raise
                log.info("├── Retrieving dir metadata ...")
                metadata       = client.head_object(Bucket=bucket, Key=key['Key'])

                dirname        = key['Key']
                atime          = get_time_in_secs(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-atime'])
                mtime          = get_time_in_secs(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-mtime'])
                owner          = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-owner'])
                group          = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-group'])
                permissions    = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-permissions'][-4:], base=8)
                perms_to_print = metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-permissions'][-4:]

                element        = { 'dirname': dirname, 'atime': atime, 'mtime': mtime, 'owner': owner, 'group': group, 'permissions': permissions, 'perms_to_print': perms_to_print }

                md.append(element)

                log.info("└── Done!\n")
            else:
                object_versions = s3.Bucket(bucket).object_versions.filter(Prefix=str(key['Key']))
                for object_version in object_versions:
                       obj                = object_version.get()
                       obj_date           = obj.get('LastModified')
                       obj_version_id     = obj.get('VersionId')
                       obj_content_length = obj.get('ContentLength')
                       if obj_date <= restore_date:
                           log.info("Restoring file: {} ...".format(str(key['Key'])))
                           if single_file_restore:
                              Path(os.path.split(tgtobj)[0]).mkdir(parents=True, exist_ok=True)
                           client.download_file(bucket, key['Key'], tgtobj, ExtraArgs={"VersionId": obj_version_id})
                           size, label = format_bytes(obj_content_length)
                           log.info("├── Data ")
                           log.info("├───── destination file: {} ".format(tgtobj))
                           log.info("├───── version: {}".format(obj_version_id))
                           log.info("├───── date: {}".format(obj_date))
                           log.info("├───── {}: {}".format(label, round(size)))
                           log.info("├── Done!")
                           total_size = total_size + obj_content_length
                           log.info("├── Retrieving file metadata ...")
                           metadata       = client.head_object(Bucket=bucket, Key=key['Key'], VersionId=obj_version_id)

                           atime          = get_time_in_secs(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-atime'])
                           mtime          = get_time_in_secs(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-mtime'])
                           owner          = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-owner'])
                           group          = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-group'])
                           permissions    = int(metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-permissions'][-4:], base=8)
                           perms_to_print = metadata['ResponseMetadata']['HTTPHeaders']['x-amz-meta-file-permissions'][-4:]
                           log.info("├── Done!")
                           log.info("├── Applying metadata ...")
                           log.info("├───── atime: {} {}".format(atime, datetime.datetime.fromtimestamp(atime)))
                           log.info("├───── mtime: {} {}".format(mtime, datetime.datetime.fromtimestamp(mtime)))
                           log.info("├───── owner: {}".format(owner))
                           log.info("├───── group: {}".format(group))
                           log.info("├───── permissions: {}".format(perms_to_print))
                           try:
                               os.chown(tgtobj, owner, group)
                               os.chmod(tgtobj, permissions)
                               os.utime(tgtobj, times=(atime,mtime))
                           except BaseException as e:
                               raise
                           log.info("└── Done!\n")
                           break
    md.reverse()
    for element in md:
       log.info("Applying directory metadata ...")
       log.info("├───── dir: {}".format(element['dirname']))
       log.info("├───── atime: {} {}".format(element['atime'], datetime.datetime.fromtimestamp(element['atime'])))
       log.info("├───── mtime: {} {}".format(element['mtime'], datetime.datetime.fromtimestamp(element['mtime'])))
       log.info("├───── owner: {}".format(element['owner']))
       log.info("├───── group: {}".format(element['group']))
       log.info("├───── permissions: {}".format(element['perms_to_print']))

       try:
           os.chown(target + "/" + element['dirname'], element['owner'], element['group'])
           os.chmod(target + "/" + element['dirname'], element['permissions'])
           os.utime(target + "/" + element['dirname'], times=(element['atime'],element['mtime']))
       except BaseException as e:
           raise
       log.info("└── Done!\n")


    log.info("Total objects restored : {}".format(total_objs))
    size, label = format_bytes(total_size)
    log.info("Total {} restored: {}".format(label, round(size,2)))



"""
MAIN
"""

utc = pytz.UTC

start_time = time.monotonic()

"""
Setting the arguments
"""
parser = argparse.ArgumentParser(description='Restore of Lustre files from S3 to a local path.')
parser.add_argument('-b','--bucket', help='S3 Bucket where the files are stored.', required=True)
parser.add_argument('-p','--remote-path', help='Remote path of the files/dirs that will be restored.', required=True)
parser.add_argument('-d','--local-dir', help='Local directory where the files/dirs will be restored.', required=True)
parser.add_argument('-t','--date-time', help='Restore point date and time in UTC format. Set to now if not provided.', required=False, type=valid_date)
parser.add_argument('-v','--verbose', help='Output on console and logfile.', action='store_true')
args        = vars(parser.parse_args())
bucket      = args['bucket']
remote_path = args['remote_path']
local_dir   = args['local_dir']
verbose     = args['verbose']

if args['date_time'] is None:
    restore_point_date = datetime.datetime.now(datetime.timezone.utc)
else:
    restore_point_date = utc.localize(datetime.datetime.fromisoformat(args['date_time']), is_dst=None)

"""
Configuring the logging
"""
logfilename = datetime.datetime.now().strftime('restore_from_s3r-%Y%m%d-%H%M%S.log')
FORMAT = "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
logging.basicConfig(filename=logfilename, filemode='a', level="INFO", format=FORMAT)


if verbose:
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    formatter = logging.Formatter(FORMAT)
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(RichHandler())
else:
    print("Logfile: {}".format(logfilename))

# log = logging.getLogger(__name__)
# logging.basicConfig(filename=logfilename, filemode='a', level="INFO", format=FORMAT, handlers=[RichHandler()] )
log = logging.getLogger("rich")



"""
Connecting to AWS
"""
client = boto3.client('s3')
s3     = boto3.resource('s3')

"""
Calling restore function
"""
restore_from_s3(client, bucket, remote_path, local_dir, restore_point_date)

end_time = time.monotonic()
log.info('Duration: {}'.format(datetime.timedelta(seconds=end_time - start_time)))
