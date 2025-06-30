#!/usr/bin/env python3
#%%
from jinja2 import Template
# import boto3
import json

import cloudpathlib
import json
import os
from tap import Tap
from enum import Enum, auto
import sys
import configparser
from anytree import Node, RenderTree
from anytree import Node

class PolicyType(Enum):
    NO_ACCESS = auto()
    FULL_ACCESS = auto()
    READ_ONLY = auto()
    READ_WRITE = auto()

class Args(Tap):
    """Command line arguments parser."""
    bucket_name: str = ""  # Default bucket name
    # Add aliases for command line: -b and --bucket_name
    user_name: str = ""  # Default new user name  
    get_policy: bool = False  # Flag to get policy
    update_policy: bool = False  # Flag to update policy
    policy_type:int = -1  # No default policy type, will be set by user input
    config_file = "~/.s3cfg"  # Default config file path
    list : bool = False  # Flag to list all buckets
    delete_policy: bool = False  # Flag to delete policy for a user
    
    def configure(self):
        self.add_argument("-b", "--bucket_name", help="Bucket name", default="")
        self.add_argument("-g", "--get_policy", help="Get current policy", default=False, action='store_true')
        self.add_argument("-u", "--update_policy", help="Update policy", default=False, action='store_true')
        self.add_argument("-n", "--user_name", help="User name", default="")
        self.add_argument("-t", "--policy_type", type=int, choices=list([1,2,3,4]), help="Policy type 1=NO_ACCESS, 2=FULL_ACCESS, 3=READ_ONLY, 4=READ_WRITE", default=-1)
        self.add_argument("-c", "--config_file", help="Path to the S3 config file", default=self.config_file)
        self.add_argument("-l", "--list", help="List all buckets", default=False, action='store_true')
        self.add_argument("-d", "--delete_policy", help="Delete policy", default=False, action='store_true') 
    
    def validate(self):                
        if not self.bucket_name or not isinstance(self.bucket_name, str):
            raise ValueError("bucket_name must be a non-empty string")
        
        if (not self.user_name or not isinstance(self.user_name, str)) and not (self.get_policy or self.list or self.delete_policy):
            raise ValueError("user_name must be a non-empty string")
        
        if (not self.get_policy) and (not self.update_policy) and (not self.list) and (not self.delete_policy):
            raise ValueError("Select at least on of the options --get_policy or --update_policy or --list or --delete_policy")
        
        if self.get_policy and self.update_policy:
            raise ValueError("Cannot get and update policy at the same time. Choose one action.")
        
        if self.policy_type not in [1, 2, 3, 4] and self.update_policy:
            raise ValueError("policy_type must be 1 (NO_ACCESS), 2 (FULL_ACCESS), or 3 (READ_ONLY), 4 (READ_WRITE)")
        
        if self.policy_type==-1 and not self.update_policy and not (self.get_policy or self.list or self.delete_policy):
            raise ValueError("policy_type must be set to 1 (NO_ACCESS), 2 (FULL_ACCESS), or 3 (READ_ONLY) when updating policy. Use --update_policy to update the policy.")
        
        if self.policy_type not in [1, 2, 3, 4] and not self.update_policy and not (self.get_policy or self.list or self.delete_policy):        
            raise ValueError("To update the policy use the -u flag")

    def __str__(self):
        return f"Args(bucket_name={self.bucket_name}, user_name={self.user_name}, get_policy={self.get_policy}, update_policy={self.update_policy}, policy_type={self.policy_type}, config_file={self.config_file}), list={self.list}, delete_policy={self.delete_policy})"        


# No access template (deny all actions to everyone)
no_access_template = """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Principal": {"AWS": ["arn:aws:iam::sils_mns:user/{{user_name}}"]},
        "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:DeleteObject"
    ],
        "Resource": [
            "arn:aws:s3:::{{ bucket_name }}",
            "arn:aws:s3:::{{ bucket_name }}/*"
        ]
    }]
}"""

# Full access template (allow all actions to everyone)
full_access_template = """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": ["arn:aws:iam::sils_mns:user/{{user_name}}"]},
        "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:DeleteObject"
    ],
        "Resource": [
            "arn:aws:s3:::{{ bucket_name }}",
            "arn:aws:s3:::{{ bucket_name }}/*"
        ]
    }]
}"""

# Read-only access template (allow only GetObject and ListBucket)
read_only_access_template = """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": ["arn:aws:iam::sils_mns:user/{{user_name}}"]},
        "Action": [
            "s3:GetObject",
            "s3:ListBucket"
        ],
        "Resource": [
            "arn:aws:s3:::{{ bucket_name }}",
            "arn:aws:s3:::{{ bucket_name }}/*"
        ]
    }]
}"""


def read_s3cfg(config_file):    
    s3cfg_path = os.path.expanduser(config_file)
    if os.path.exists(s3cfg_path):
        config = configparser.ConfigParser()
        config.read(s3cfg_path)
        # s3cmd config uses 'default' section or no section
        section = 'default' if 'default' in config else config.sections()[0] if config.sections() else None
        if section:
            access_key = config.get(section, 'access_key', fallback="")
            secret_key = config.get(section, 'secret_key', fallback="")
            host_base = config.get(section, 'host_base', fallback="")
            return access_key, secret_key, host_base
    return None, None, None

def configure_s3_client(config_file):
    """Configure the S3 client using credentials from ~/.s3cfg or environment variables."""
    access_key_id, secret_access_key, endpoint = read_s3cfg(config_file)
    
    if not access_key_id or not secret_access_key or not endpoint:
        access_key_id = os.getenv("S3_ACCESS_KEY", "")
        secret_access_key = os.getenv("S3_SECRET_KEY", "")
        endpoint = os.getenv("S3_ENDPOINT", "")

    if not access_key_id or not secret_access_key or not endpoint:
        raise ValueError("S3 credentials and endpoint must be set either in ~/.s3cfg or as environment variables (S3_ACCESS_KEY, S3_SECRET_KEY, S3_ENDPOINT).") 

    client = cloudpathlib.S3Client(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        endpoint_url=endpoint,
    )

    client.set_as_default_client()
    return client.client


def list_buckets(s3, bucket_name):
    """
    List all S3 buckets or the contents of a specific bucket, and return a tree of Nodes.
    """

    root = Node("root")
    try:
        if bucket_name:
            # If a specific bucket is provided, check if it exists
            s3.head_bucket(Bucket=bucket_name)
            bucket_node = Node(bucket_name, parent=root)
            # List contents of the bucket
            response = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                for obj in response['Contents']:
                    parts = obj['Key'].split('/')
                    parent = bucket_node
                    for part in parts:
                        existing = next((n for n in parent.children if n.name == part), None)
                        if existing:
                            parent = existing
                        else:
                            parent = Node(part, parent=parent)
            # If bucket is empty, just return the bucket node
        else:
            # List all buckets
            response = s3.list_buckets()
            for bucket in response['Buckets']:
                Node(bucket['Name'], parent=root)
        return root
    except Exception as e:
        print(f"Error listing buckets: {e}")
        return root

def get_bucket_policy(s3, bucket_name):
    
    """Get the S3 bucket policy."""
    try:       
        root_bucket = bucket_name.split('/')[0] if '/' in bucket_name else bucket_name
        policy = s3.get_bucket_policy(Bucket=root_bucket)
        return policy
        # return json.loads(policy['Policy'])
    except Exception as e:
        print(f"Error getting bucket policy: {e}")
        return None 

def update_policy(s3, bucket_name, user_name, policy_type:int = -1):
    """Update the S3 bucket policy to add a new user."""
    try:
        
        if policy_type == -1:
            raise ValueError("policy_type must be set to 1 (NO_ACCESS), 2 (FULL_ACCESS), or 3 (READ_ONLY) when updating policy. Use --update_policy to update the policy.")

        template = no_access_template
        if policy_type == 2:
            template = full_access_template
        elif policy_type == 3:
            template = read_only_access_template
        # Render the template with the bucket name and new user name
        new_policy = Template(template).render(bucket_name=bucket_name, user_name=user_name)


        # Get the existing bucket policy
        root_bucket = bucket_name.split('/')[0]
        policy = get_bucket_policy(s3, root_bucket)
        if not policy:
            s3.put_bucket_policy(Bucket=root_bucket, Policy=new_policy)
            print(f"Created new bucket policy for user: {user_name}")
            return

        new_policy_statement = json.loads(new_policy)['Statement'][0]               
        
        # There is a policy
        policy_dict = json.loads(policy['Policy'])
                
        # Add the new statement to the policy
        policy_dict['Statement'].append(new_policy_statement)

        # Convert back to JSON
        # Pretty-print the updated policy for terminal readability
        updated_policy = json.dumps(policy_dict, indent=2, ensure_ascii=False)
   

        # Update the bucket policy
        s3.put_bucket_policy(Bucket=root_bucket, Policy=updated_policy)

        print(f"Updated bucket policy with new user: {user_name}")
    except Exception as e:
        print(f"Error updating policy: {e}")


def delete_policy_for_user(s3, bucket_name, user_name):
    """Delete the S3 bucket policy for a specific user."""
    try:
        # Get the existing bucket policy
        policy = get_bucket_policy(s3, bucket_name)
        if not policy:
            print(f"No policy found for bucket: {bucket_name}")
            return

        # Load the existing policy as a dict
        policy_dict = json.loads(policy['Policy'])

        # Remove the statement for the specified user
        policy_dict['Statement'] = [
            stmt for stmt in policy_dict['Statement']
            for string in stmt.get('Principal', {}).get('AWS', [])
            if user_name not in string
        ]

        # Convert back to JSON
        updated_policy = json.dumps(policy_dict)

        # Update the bucket policy
        root_bucket = bucket_name.split('/')[0]
        s3.put_bucket_policy(Bucket=root_bucket, Policy=updated_policy)

        print(f"Deleted policy for user: {user_name} in bucket: {bucket_name}")
    except Exception as e:
        print(f"Error deleting policy: {e}")


def delete_policy(s3, bucket_name):
    """Delete the S3 bucket policy for a specific user."""
    try:
        # Get the existing bucket policy
        policy = get_bucket_policy(s3, bucket_name)
        if not policy:
            print(f"No policy found for bucket: {bucket_name}")
            return
        
        s3.delete_bucket_policy(Bucket=bucket_name)
    
    except Exception as e:
        print(f"Error deleting bucket policy: {e}")



#%%
if __name__ == "__main__":

    args = Args().parse_args()

    print("Parsed arguments:", args)

    try:
        args.validate()
    except Exception as e:
        print(f"Argument validation error: {e}")
        sys.exit(1)

    s3 = configure_s3_client(args.config_file)    

    # Get the bucket policy if requested
    if args.get_policy:
        policy = get_bucket_policy(s3, args.bucket_name)
        if policy:         
            policy_dict = json.loads(policy['Policy'])
            current_policy = json.dumps(policy_dict, indent=4, ensure_ascii=False)
            print("Current Bucket Policy:", current_policy)

    
    # # Update the bucket policy if requested
    if args.update_policy:
        update_policy(s3, args.bucket_name, args.user_name, args.policy_type)
        print(f"Policy updated for user: {args.user_name} in bucket: {args.bucket_name}")

    if args.delete_policy and args.user_name:
        policy = get_bucket_policy(s3, args.bucket_name)
        if policy:         
            policy_dict = json.loads(policy['Policy'])
            current_policy = json.dumps(policy_dict, indent=4, ensure_ascii=False)
            print("Current Bucket Policy:", current_policy)
        delete_policy_for_user(s3, args.bucket_name, args.user_name)
        
    
    if args.delete_policy and not args.user_name:
        policy = get_bucket_policy(s3, args.bucket_name)
        if policy:         
            policy_dict = json.loads(policy['Policy'])
            current_policy = json.dumps(policy_dict, indent=4, ensure_ascii=False)
            print("Current Bucket Policy:", current_policy)

        delete_policy(s3, args.bucket_name)
        print(f"All policies deleted in bucket: {args.bucket_name}")

    # # Update the bucket policy if requested
    if args.list:
        nodes = list_buckets(s3, args.bucket_name)
        print("Listing buckets and their contents:")
        for pre, _, node in RenderTree(nodes):
            print("%s%s" % (pre, node.name))

    
