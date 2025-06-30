# s3-tools
## S3 - utility

### Easily update/modify policies for ceph/s3 shares

**usage: s3.py [-b BUCKET_NAME] [-n USER_NAME] [-g] [-u] [-t {1,2,3,4}] [-c CONFIG_FILE] [-l] [-d] [-h]**

Command line arguments parser.

options:   
  -b, --bucket_name BUCKET_NAME  
  -n, --user_name USER_NAME  
  -g, --get_policy      Get current policy  
  -u, --update_policy   Update policy  
  -t, --policy_type {1,2,3,4}  -> type 1=NO_ACCESS, 2=FULL_ACCESS, 3=READ_ONLY, 4=READ_WRITE   
  -c, --config_file CONFIG_FILE  -> Path to the S3 config file   
  -l, --list            -> List all buckets  
  -d, --delete_policy   -> Delete the policy for the bucket (if with -n delete for user only)  
  -h, --help            -> show this help message and exit  

## In case of no s3 config file
The access key, secret access key and endpoint can also be defined as environment variables  

* **S3_ACCESS_KEY**  
* **S3_SECRET_KEY**  
* **S3_ENDPOINT**  
 

## Example usages

1. List bucket(s)
```{bash}
s3.py -b <BUCKET_NAME> -l
```
2. Get bucket policy
```{bash}
s3.py -b <BUCKET_NAME> -g
```

3. Set bucket policy for user
```{bash}
s3.py -b <BUCKET_NAME> -n <USERNAME> -t 1
```

4. Delete bucket policy for user
```{bash}
s3.py -b <BUCKET_NAME> -n <USERNAME> -d
```

5. Delete all bucket policies 
```{bash}
s3.py -b <BUCKET_NAME> -d
```
