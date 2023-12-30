import pulumi
import pulumi_aws as aws
import yaml,os,json

config = pulumi.Config("aws");
region = config.require("region")

# Load configuration from dev.yaml file
with open('variables.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

# Extract VPC name from configuration
vpc_name = config['vpc_name']

#IAM account-id
account_id=config['account_id']

#bastion EC2
instancetype=config['instancetype']
instance_name=config['instance_name']

#Webserver EC2
webserver_instancetype=config['webserver_instancetype']
webserver_instancename=config['webserver_instancename']

#ElasticSearch
ES_clustername=config['ES_clustername']
ES_version=config['ES_version']
ES_instance_type=config['ES_instance_type']

#rds
rdssnapshotname=config['rdssnapshotname']
rdsusername=config['rdsusername']
rdspassword=config['rdspassword']
rdsinstance_class=config['rdsinstance_class']
rdsstorage_type=config['rdsstorage_type']
rds_engine=config['rds_engine']

#ElasticCache
redisNodeType=config['redisNodeType']

#rabbitMQ
rabbitMQ_engine_version=config['rabbitMQ_engine_version']
rabbitMQ_host_instance_type=config['rabbitMQ_hostinstance_type']
rabbitMQ_username=config['rabbitMQ_username']
rabbitMQ_password=config['rabbitMQ_password']
rabbitMQ_broker_name=config['rabbitMQ_broker_name']
rabbitMQ_cloudwatch_enabled=config['rabbitMQ_cloudwatch_enabled']

#eks
cluster_name=config['cluster_name']
eks_version=config['eks_version']

#eks nodegroup
nodegroup_ami_type=config['nodegroup_ami_type']
nodegroup_instance_type=config['nodegroup_instance_type']

#EFS
efs_status=config['status']
efs_Name=config['efs_Name']

#Lambda
lambda_function_code_path=config['lambda_function_code_path']
lambda_python_runtime=config['lambda_python_runtime']

# Create a new VPC
vpc = aws.ec2.Vpc("vpc_name",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    tags={"Name": vpc_name},
    opts=pulumi.ResourceOptions(provider=aws.Provider("aws", region=region))
)

# Create three public subnets
public_subnets = []
for i,az in enumerate(["a", "b", "c"]):
    public_subnet = aws.ec2.Subnet(f"public-subnet-{i}-{vpc_name}",
        vpc_id=vpc.id,
        cidr_block=f"10.0.{i+1}.0/24",
        availability_zone=f"{region}{az}",
        tags={"Name": f"public-subnet-{i}"}
    )
    public_subnets.append(public_subnet)


# Create an Internet Gateway and attach it to the VPC
igw = aws.ec2.InternetGateway(f"my-igw-{vpc_name}",
    vpc_id=vpc.id,
    opts=pulumi.ResourceOptions(provider=aws.Provider("igw", region=region))
)

# Create a NAT Gateway in each availability zone and allocate an Elastic IP for each
nat_gateways = []
for i, az in enumerate(["a", "b", "c"]):
    eip = aws.ec2.Eip(f"nat-gateway-eip-{i}")
    nat_gateway = aws.ec2.NatGateway(f"nat-gateway-{i}-{vpc_name}",
        subnet_id=public_subnets[i].id,
        allocation_id=eip.id,
    )
    nat_gateways.append(nat_gateway)

# Create a public route table and add a route to the Internet Gateway
public_route_table = aws.ec2.RouteTable(f"public-route-table-{vpc_name}",
    vpc_id=vpc.id,
    tags={"Name": "public-route-table"}
)

for i, subnet in enumerate(public_subnets):
    aws.ec2.RouteTableAssociation(f"public-subnet-association-{i}-{vpc_name}",
        route_table_id=public_route_table.id,
        subnet_id=subnet.id,
    )

    aws.ec2.Route(f"public-route-{i}",
        route_table_id=public_route_table.id,
        destination_cidr_block="0.0.0.0/0",
        gateway_id=igw.id,
    )

# Create three private subnets (one in each AZ) with respective route tables and NAT gateway associations
private_subnets = []
private_route_tables = []
private_subnet_associations = []

for i, az in enumerate(["a", "b", "c"]):
    # Create private subnet
    private_subnet = aws.ec2.Subnet(f"private-subnet-{i}-{vpc_name}",
        vpc_id=vpc.id,
        cidr_block=f"10.0.{i+4}.0/24",
        availability_zone=f"{region}{az}",
        tags={"Name": f"private-subnet-{i}-{vpc_name}"}
    )
    private_subnets.append(private_subnet)

    # Create route table for the private subnet
    private_route_table = aws.ec2.RouteTable(f"private-route-table-{i}-{vpc_name}",
        vpc_id=vpc.id,
        tags={"Name": f"private-route-table-{i}-{vpc_name}"}
    )
    private_route_tables.append(private_route_table)

    # Associate private subnet with the respective route table
    private_subnet_association = aws.ec2.RouteTableAssociation(f"private-subnet-association-{i}-{vpc_name}",
        route_table_id=private_route_table.id,
        subnet_id=private_subnet.id,
    )
    private_subnet_associations.append(private_subnet_association)

    # Create route in the private route table with the associated NAT gateway
    aws.ec2.Route(f"private-route-{i}-{vpc_name}",
        route_table_id=private_route_table.id,
        destination_cidr_block="0.0.0.0/0",
        nat_gateway_id=nat_gateways[i].id,
    )

#Bastion security group
Bastionsecurity_group = aws.ec2.SecurityGroup(f"Bastion_Security_Group-{vpc_name}",
    name = "Bastion-SG",
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=22,
            to_port=22,
            cidr_blocks=["0.0.0.0/0"],
        )
    ],
        egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        )
    ]
)

#WebServer security group
EKS_security_group = aws.ec2.SecurityGroup(f"EKS_SG-{vpc_name}",
    name="EKS-SG",                                    
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=22,
            to_port=22,
            security_groups=[Bastionsecurity_group.id],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["10.0.0.0/16"],
        )
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        )
    ]
)

with open(os.path.expanduser("~/.ssh/id_rsa.pub"), "r") as pub_key_file:
    public_key = pub_key_file.read().strip()

# Create AWS EC2 Key Pair resource
my_key_pair = aws.ec2.KeyPair("my_key_pair",
                              key_name="my_key",
                              public_key=public_key)

# Export the Key Pair ID
pulumi.export("KeyPairId", my_key_pair.id)


#Create Bastion Server
instance = aws.ec2.Instance(instance_name,
   instance_type=instancetype,
   ami=aws.ec2.get_ami(most_recent=True,
       filters=[
           aws.ec2.GetAmiFilterArgs(
               name="name",
               values=["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
           ),
           aws.ec2.GetAmiFilterArgs(
               name="virtualization-type",
               values=["hvm"]
           )
       ],
       owners=["099720109477"]  # Canonical
   ).id,
   subnet_id=public_subnets[0].id,
   vpc_security_group_ids=[Bastionsecurity_group.id],  # Associate security group with instance
   root_block_device={
       "volumeType": "gp3",
       "volumeSize": 8
   },
   associate_public_ip_address=False,
   key_name=my_key_pair.key_name,
   tags={
       'Name': f'Bastion-{vpc_name}', 
   }
)


ec2_role = aws.iam.Role("ec2_role", assume_role_policy="""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}""")

eks_full_access_policy = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "eks:DescribeCluster",
                "eks:ListClusters",
                "eks:ListFargateProfiles",
                "eks:ListUpdates",
                "eks:AccessKubernetesApi"
            ],
            "Resource": "*"
        }
    ]
}"""

eks_full_access_policy = aws.iam.Policy(
    "eks_full_access_policy",
    policy=eks_full_access_policy
)

role_policy_attach_to_eks = aws.iam.RolePolicyAttachment("eks_full_access_policy",role=ec2_role.id, policy_arn=eks_full_access_policy.arn)

attach_policy_to_ec2_role=[
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
]

for i,policy in enumerate(attach_policy_to_ec2_role):
    role_policy_attach_to_eks = aws.iam.RolePolicyAttachment(f"{i,}policy", role=ec2_role.id, policy_arn=policy)

instance_profile = aws.iam.InstanceProfile('new_profile', role=ec2_role)

#Create WebServer
WS_instance = aws.ec2.Instance(webserver_instancename,
   instance_type=webserver_instancetype,
   iam_instance_profile=instance_profile,
   ami=aws.ec2.get_ami(most_recent=True,
       filters=[       
           aws.ec2.GetAmiFilterArgs(
               name="name",
               values=["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
           ),
           aws.ec2.GetAmiFilterArgs(
               name="virtualization-type",
               values=["hvm"]
           )
       ],
       owners=["099720109477"]  # Canonical
   ).id,
   subnet_id=private_subnets[0].id,
   vpc_security_group_ids=[EKS_security_group.id],  # Associate security group with instance
   root_block_device={
       "volumeType": "gp3",
       "volumeSize": 40
   },
   associate_public_ip_address=False,
   key_name=my_key_pair.key_name,
   tags={
       'Name': f'WebServer-{vpc_name}', 
   }
)


elastic_ip = aws.ec2.Eip("my_eip")
eip_assoc = aws.ec2.EipAssociation("eip_assoc",
                                   instance_id = instance.id,
                                   public_ip=elastic_ip.public_ip)

rdssecurity_group = aws.ec2.SecurityGroup(f"RDSSecurityGroup-{vpc_name}",
    vpc_id=vpc.id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="TCP",
            from_port=5432,
            to_port=5432,
            security_groups=[EKS_security_group.id],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["10.0.0.0/16"],
        )
        ],
        egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        )
    ],

)

private_subnet_ids = [subnet.id for subnet in private_subnets]

rds_subnet_group = aws.rds.SubnetGroup("rds-subnet-group",
    subnet_ids=private_subnet_ids,
    tags={"Name": "rds-subnet-group"}
)

def get_snapshot_id(db_snapshot):
    if db_snapshot:
        return db_snapshot.id    
    else:
        print("inside else no snapshot")
        return None

snapshot_id = None
try:
    # Retrieve the most recent snapshot of a specified RDS DB instance.
    most_recent_snapshot = aws.rds.get_snapshot(most_recent=True, db_instance_identifier=rdssnapshotname)
    most_recent_snapshot_output = pulumi.Output.from_input(most_recent_snapshot)
    snapshot_id = most_recent_snapshot_output.apply(get_snapshot_id)

    # Export the snapshot ID for use in other stacks, if needed.
    pulumi.export('snapshotId', most_recent_snapshot.id)
    
except Exception as e:  # Handle exception if snapshot is not found
    pulumi.log.error("An error occurred while retrieving the snapshot or no snapshot found")
    pulumi.log.error(str(e))

#Create a new AWS RDS instance from the latest snapshot if it exists, otherwise create a new database
rds_from_snapshot = aws.rds.Instance('rdsfromsnapshot',
    identifier="rds-instance",  
    instance_class=rdsinstance_class,
    snapshot_identifier=snapshot_id,
    allocated_storage=50,
    engine=rds_engine,
    storage_type=rdsstorage_type,
    username=rdsusername,
    password=rdspassword,
    port=5432,
    vpc_security_group_ids=[
        rdssecurity_group.id
    ],
    db_subnet_group_name=rds_subnet_group.name,
    skip_final_snapshot=True
)

rds_endpoint = rds_from_snapshot.endpoint
pulumi.export("RDS",rds_from_snapshot.endpoint)


redissecurity_group = aws.ec2.SecurityGroup('redis_security_group',
    name = "redis_security_group",
    description='Enable inbound traffic on port 6379',
    ingress=[
        {
            'protocol': 'tcp',
            'from_port': 6379,
            'to_port': 6379,
            'cidr_blocks': ['0.0.0.0/0'],
        },
    ],
    egress=[
        {
            'protocol': '-1',
            'from_port': 0,
            'to_port': 0,
            'cidr_blocks': ['0.0.0.0/0'],
            'ipv6_cidr_blocks': ['::/0'],
        },
    ],
)

subnet_group = aws.elasticache.SubnetGroup('redis-subnet-group',
    subnet_ids=private_subnet_ids,
    tags={"Name": "redis-subnet-group"}
)

#Create a replication group based on the cluster
replication_group = aws.elasticache.ReplicationGroup('redis-replication-group',
    automatic_failover_enabled=True,
    description='A AWS ElastiCache Replication Group',
    replication_group_id='redis-replication-group',
    # A minimum of two caches in a replication group is needed
    num_cache_clusters=2,
    node_type=redisNodeType,
    port=6379,  
    subnet_group_name=subnet_group.name,
    security_group_ids=[EKS_security_group.id],
    multi_az_enabled=True,
)

#Print the primary endpoint address (the writing endpoint) in the output
pulumi.export("primary_endpoint_address", replication_group.primary_endpoint_address)

pulumi.export("ElasticIpId", elastic_ip.id)

# Export the instance's endpoint
pulumi.export('rds_endpoint', rds_from_snapshot.endpoint)


# Export the VPC ID and subnet IDs for use in other stacks
pulumi.export("vpc_id", vpc.id)
for i, subnet in enumerate(public_subnets + private_subnets):
    pulumi.export(f"subnet_{i}_id", subnet.id)


rabbitmq_security_group = aws.ec2.SecurityGroup('rabbitmq_security_group',
    name = "rabbitmq_security_group",
    description='Enable all traffic from webserver to rabbitmq',
    vpc_id=vpc.id, 
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=0,
            to_port=65535,
            security_groups=[EKS_security_group.id],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["10.0.0.0/16"],
        )
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        )
    ]
)

rabbitmq_broker = aws.mq.Broker(rabbitMQ_broker_name,
    broker_name=rabbitMQ_broker_name,
    deployment_mode="SINGLE_INSTANCE",
    engine_type="RabbitMQ",
    engine_version=rabbitMQ_engine_version,
    host_instance_type=rabbitMQ_host_instance_type,
    security_groups=[rabbitmq_security_group.id],  
    subnet_ids=[private_subnet_ids[0]],
    auto_minor_version_upgrade=True,
    apply_immediately=True,
    logs = aws.mq.BrokerLogsArgs(
        general=rabbitMQ_cloudwatch_enabled,
    ),
    users=[
        aws.mq.BrokerUserArgs(
            username=rabbitMQ_username,
            password=rabbitMQ_password,
            console_access = True
        ),
    ],
    maintenance_window_start_time={
        'day_of_week': 'SUNDAY',
        'time_of_day': '20:00',
        'time_zone': 'UTC',
    },
    tags={
        'Name': 'pulumiRabbitMQ', 
    }   
)

pulumi.export('rabbitMQ_broker_url', rabbitmq_broker.instances[0]["console_url"])
pulumi.export('rabbitMQ_broker_endpoints', rabbitmq_broker.instances[0]["endpoints"][0])

es_kms_key = aws.kms.Key("kms_key")

access_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "es:*",
            "Resource": "*"
        }
    ]
}

additional_configurations = {
    "rest.action.multi.allow_explicit_index": "true",
    "indices.query.bool.max_clause_count": "10000"
}


# Create an Elasticsearch domain
elasticsearch_domain = aws.elasticsearch.Domain(ES_clustername,
    domain_name=ES_clustername,                                 
    access_policies=pulumi.Output.from_input(access_policy).apply(lambda x: json.dumps(x)),
    encrypt_at_rest={
        "enabled": True,
        "kms_key_id": es_kms_key.key_id
    },   
    node_to_node_encryption={
        'enabled': True
    },                                             
    elasticsearch_version=ES_version,
    cluster_config={
        "instance_count": 3,
        "instance_type": ES_instance_type,
        "zone_awareness_enabled": True,
        "zone_awareness_config": {
            "availability_zone_count": 3
        },
    },
    ebs_options={
        "ebs_enabled": True,
        "volume_size": 20,  # Define as per your requirement
    },
    vpc_options={
        # These IDs will depend on the VPC and subnets that you have.
        "subnet_ids": private_subnet_ids,
        "security_group_ids": [EKS_security_group.id],
    },
    advanced_options=additional_configurations,
    domain_endpoint_options={
        "enforce_https": True,
        "tls_security_policy": "Policy-Min-TLS-1-2-2019-07"
    },
)

pulumi.export("elasticsearch_domain_arn", elasticsearch_domain.arn)
pulumi.export("elasticsearch_endpoint", elasticsearch_domain.endpoint)

status = efs_status
efs_kms_key = aws.kms.Key("efs_kms_key")

if status:
    efs_filesystem = aws.efs.FileSystem(
        "my_file_system",
        performance_mode="generalPurpose",
        throughput_mode="bursting",
        encrypted=True,
        kms_key_id=efs_kms_key.arn,
        tags={
            "Name": efs_Name ,
        }
    )

    # Create EFS Mount Targets
    efs_mount_targets = []
    for idx, subnet_id in enumerate(private_subnet_ids, start=1):
        efs_mount_target = aws.efs.MountTarget(
            f"efsMountTarget{idx}",
            file_system_id=efs_filesystem.id,
            subnet_id=subnet_id,
            security_groups=[EKS_security_group.id]
        )
        efs_mount_targets.append(efs_mount_target)

    # Enable automatic backups
    efs_backup_policy = aws.efs.BackupPolicy(
        "my_backup_policy",
        file_system_id=efs_filesystem.id,
        backup_policy={
            'status': 'ENABLED',
        }
    )

#Create EKS security group
eks_security_group = aws.ec2.SecurityGroup(f"eks-{vpc_name}",
    vpc_id=vpc.id,
    description="Communication between the control plane and worker nodegroups",
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        )
    ]
)
AWSEFSController = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:CreateAccessPoint"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:RequestTag/efs.csi.aws.com/cluster": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:TagResource"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "elasticfilesystem:DeleteAccessPoint",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
        }
      }
    }
  ]
}

AWSLoadBalancerController ={
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL",
                "shield:GetSubscriptionState",
                "shield:DescribeProtection",
                "shield:CreateProtection",
                "shield:DeleteProtection"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "StringEquals": {
                    "ec2:CreateAction": "CreateSecurityGroup"
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:DeleteRule"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ],
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeleteTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:SetWebAcl",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:ModifyRule"
            ],
            "Resource": "*"
        }
    ]
}
                
#IAM role for EKS NodeGroup
eks_role = aws.iam.Role("eks_cluster_role", assume_role_policy="""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}""")


attach_policy_to_eks_role=[
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
]

for policy in attach_policy_to_eks_role:
    role_policy_attach_to_eks = aws.iam.RolePolicyAttachment(policy, role=eks_role.id, policy_arn=policy)

#Create the EKS cluster
eks_cluster = aws.eks.Cluster(
    cluster_name,
    name=cluster_name,
    role_arn=eks_role.arn,
    version=eks_version,
    vpc_config=aws.eks.ClusterVpcConfigArgs(
        subnet_ids=private_subnet_ids,
        endpoint_private_access=True,
        endpoint_public_access=False,
        public_access_cidrs=[],
        security_group_ids=[EKS_security_group.id],
    ),
    enabled_cluster_log_types=["api", "audit", "authenticator", "controllerManager", "scheduler"],
)

#Create an OIDC provider for the EKS cluster
oidc_provider = aws.iam.OpenIdConnectProvider("oidc-provider",
    url=pulumi.Output.all(eks_cluster.identities[0]['oidcs'][0]['issuer']).apply(lambda args: f"{args[0]}"),
    client_id_lists=["sts.amazonaws.com"],
    thumbprint_lists=["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
)

# Export the OIDC issuer URL 

oidc_issuer_url_str = pulumi.Output.all(eks_cluster.identities[0]['oidcs'][0]['issuer']).apply(lambda args: args[0].replace("https://", ""))
pulumi.export("oidc_issuer_url_to_str", oidc_issuer_url_str)

pulumi.export("oidc_issuer_url", eks_cluster.identities[0]['oidcs'][0]['issuer'])

vpc_cni_addon = aws.eks.Addon('vpc-cni-addon',
    addon_name='vpc-cni',
    cluster_name=cluster_name,
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster])  
)

#IAM role for EKS NodeGroup
ng_role = aws.iam.Role("eks-ng-worker", assume_role_policy="""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}""")
                                    
# Attach necessary policies to the IAM role
attach_policy_arns=[
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEKSServicePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonVPCFullAccess",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
]

for idx, policy_arn in enumerate(attach_policy_arns):
    role_attach = aws.iam.RolePolicyAttachment(f"policy_arn-{idx}", role=ng_role.id, policy_arn=policy_arn)
   

# Create EKS Nodegroup
nodegroup_0 = aws.eks.NodeGroup(
    "ng-0-production-eksworkers",
    cluster_name=cluster_name,
    ami_type=nodegroup_ami_type,
    instance_types=[nodegroup_instance_type],
    disk_size=200,
    labels={"env": "production"},
    tags={"costid": "devops"},
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=2,
        min_size=2,
        max_size=3,
    ),
    subnet_ids=private_subnet_ids,   
    node_role_arn=ng_role.arn,
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster])
)

nodegroup_1 = aws.eks.NodeGroup(
    "ng-1-production-eksworkers",
    cluster_name=cluster_name,
    ami_type=nodegroup_ami_type,
    instance_types=[nodegroup_instance_type],
    disk_size=200,
    labels={"env": "production"},
    tags={"costid": "devops"},
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=2,
        min_size=2,
        max_size=3,
    ),
    subnet_ids=private_subnet_ids,   
    node_role_arn=ng_role.arn,
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster])
)

coredns_addon = aws.eks.Addon('coredns-addon',
    addon_name='coredns',
    cluster_name=cluster_name,
    opts=pulumi.ResourceOptions(depends_on=[nodegroup_0])
)

kube_proxy_addon = aws.eks.Addon('kube-proxy-addon',
    addon_name='kube-proxy',
    cluster_name=cluster_name,
    opts=pulumi.ResourceOptions(depends_on=[nodegroup_0])
) 

#export EKS cluster ARN
pulumi.export("eks_cluster_arn", eks_cluster.arn)

arn_string = pulumi.Output.all(account_id, oidc_issuer_url_str).apply(lambda args: f"arn:aws:iam::{args[0]}:oidc-provider/{args[1]}")
pulumi.export("federated_principal", arn_string)

policy = aws.iam.Policy("AWSLoadBalancerControllerIAMPolicy-new", policy=AWSLoadBalancerController)
 
#IAM role for ALB
assume_role_policy=pulumi.Output.from_input({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Federated": pulumi.Output.concat("arn:aws:iam::",account_id,":oidc-provider/",oidc_issuer_url_str)
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    pulumi.Output.concat(oidc_issuer_url_str,":sub"): "system:serviceaccount:kube-system:aws-load-balancer-controller",
                    pulumi.Output.concat(oidc_issuer_url_str,":aud"): "sts.amazonaws.com"
                }
            }
        }
    ]
})

assume_role_policy = pulumi.Output.from_input(assume_role_policy)

ALB_Controller = aws.iam.Role('ALB_Controller',name="ALB_Controller",assume_role_policy=assume_role_policy.apply(json.dumps),opts=pulumi.ResourceOptions(depends_on=[eks_cluster]))

attachment = aws.iam.RolePolicyAttachment("AWSLoadBalancerControllerIAMPolicy-new",
    policy_arn=policy.arn,
    role=ALB_Controller.name,
)

pulumi.export('ALB_Controller_role',ALB_Controller.id)

policy = aws.iam.Policy("AWSEFSControllerPolicy", policy=AWSEFSController)
#IAM role for EFS
assume_efs_role_policy=pulumi.Output.from_input({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Federated": pulumi.Output.concat("arn:aws:iam::",account_id,":oidc-provider/",oidc_issuer_url_str)
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    pulumi.Output.concat(oidc_issuer_url_str,":sub"): "system:serviceaccount:kube-system:efs-csi-controller-sa",
                    pulumi.Output.concat(oidc_issuer_url_str,":aud"): "sts.amazonaws.com"
                }
            }
        }
    ]
})

assume_efs_role_policy = pulumi.Output.from_input(assume_efs_role_policy)

EFS_Controller = aws.iam.Role('EFS_Controller',name="EFS_Controller",assume_role_policy=assume_efs_role_policy.apply(json.dumps),opts=pulumi.ResourceOptions(depends_on=[eks_cluster]))

attachment = aws.iam.RolePolicyAttachment("AWSEFSController",
    policy_arn=policy.arn,
    role=EFS_Controller.name,
)

pulumi.export('EFS_Controller_role',EFS_Controller.id)

#SSM
#Define a custom resource to update the SSM parameter value
# class UpdateSSMParameter(pulumi.CustomResource):
#     def __init__(self,name,parameter_name,value, opts=None):
#         super().__init__(
#             "aws:ssm/parameter:Parameter",  # Use the correct type token format
#             name,
#             props={
#                 "name": parameter_name,
#                 "description": "Description of the parameter",
#                 "value": value,
#                 "type": "SecureString",  # You can use "String" for plaintext values
#                 "overwrite": True,
#             },
#             opts=opts
#         )

# parameter_names = ["/global/REDIS_HOST","/global/ES7_URL","/global/AMQP_HOST","/global/DATABASE_HOST"]

# elastic_domain = str(elasticsearch_domain.endpoint).replace("https://", "")
# rabbitmq = str(rabbitmq_broker.instances[0]["endpoints"][0]).replace("amqps://", "")
# rds_endpoint = str(rds_from_snapshot.endpoint).split(":")[0]

# #New values to set for the parameters
# new_parameter_values = {
#     "/global/REDIS_HOST":replication_group.primary_endpoint_address,
#     "/global/ES7_URL": elasticsearch_domain.endpoint,
#     "/global/AMQP_HOST": rabbitmq_broker.instances[0]["endpoints"][0],
#     "/global/DATABASE_HOST" : rds_from_snapshot.endpoint
# }

# update_ssm_parameters = []
# for param_name, param_value in new_parameter_values.items():
#     update_ssm_parameter = UpdateSSMParameter(
#         param_name,
#         param_name,
#         param_value,
#         opts=pulumi.ResourceOptions(depends_on=[replication_group,elasticsearch_domain,rds_from_snapshot,rabbitmq_broker]),
#     )
#     update_ssm_parameters.append(update_ssm_parameter)

# # Export the output of the custom resources to track their completion
# pulumi.export('update_ssm_parameter_status', [update_ssm_parameter.id for update_ssm_parameter in update_ssm_parameters])


# Create an IAM Role for Lambda
lambda_role = aws.iam.Role("lambda-role-for-jenkins",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                }
            }
        ]
    }""",
)

# Attach policies to the IAM Role
policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess",
    "arn:aws:iam::aws:policy/AWSCodeDeployFullAccess",
    "arn:aws:iam::aws:policy/AmazonVPCFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
]
# Attach a policy to the IAM Role 
for idx, lambda_policy_arn in enumerate(policy_arns):
    role_policy_attach = aws.iam.RolePolicyAttachment(f"lambda_policy_arn-{idx}", role=lambda_role.id, policy_arn=policy_arn)

# Export the ARN of the created IAM Role
pulumi.export("lambda_role_for_jenkins_arn", lambda_role.arn)

# Define the environment variables for the Lambda function
environment_variables = {
    "instance_id": WS_instance.id
}

file_archive = pulumi.AssetArchive({
    "jenkins_deployment.py": pulumi.FileAsset(lambda_function_code_path),
})

# Create the Lambda function
lambda_function = aws.lambda_.Function("jenkins-deployment-function",
    name = "jenkins-deployment-function",
    role=lambda_role.arn, 
    runtime=lambda_python_runtime,
    handler="index.lambda_handler",
    code=file_archive,
    environment={
        "variables": environment_variables,
    }
)