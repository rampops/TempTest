import re

Env = options['Env']
cidrregex = '(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?' #\b(([1-9](?:\s*[0-9]){0,2}\s*)\.(\s*[0-9](?:\s*[0-9]){0,2}\s*)\.(\s*[0-9](?:\s*[0-9]){0,2})\s*)\.(\s*[0-9](?:\s*[0-9]){0,2}\s*)\/((?:\s*[0-9]{1,2}))\b'

AvailabilityZones = [
  {'Fn::Select':[0,get_azs(ref('AWS::Region'))]},
  {'Fn::Select':[1,get_azs(ref('AWS::Region'))]}
]

# Utility functions
def ip2int(ip):
  o = map(int, ip.split('.'))
  res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
  return res


def int2ip(ipnum):
  o1 = int(ipnum / (256*256*256)) % 256
  o2 = int(ipnum / (256*256)) % 256
  o3 = int(ipnum / 256) % 256
  o4 = int(ipnum) % 256
  return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()


# Start of the CloudFormation template
description = "CloudFormation template for creating the VPC Cell 0 for {0}".format(Env)
cft = CloudFormationTemplate(description=description)

# Mappings
cft.mappings.add(Mapping(
  "NATAMI",
  {
    "us-east-1": {
      "AMI": "ami-184dc970"
    },
    "us-west-2": {
      "AMI": "ami-290f4119"
    },
    "us-west-1": {
      "AMI": "ami-a98396ec"
    },
    "eu-west-1": {
      "AMI": "ami-14913f63"
    },
    "eu-central-1": {
      "AMI": "ami-ae380eb3"
    },
    "ap-southeast-1": {
      "AMI": "ami-6aa38238"
    },
    "ap-southeast-2": {
      "AMI": "ami-893f53b3"
    }
  })
)

# parameters server cap for ASG, instance type, keypair for NAT, VPN and servers.


# ###########################
# ## The Resources Section ##
# ###########################
# Create VPC
cft.resources.add(Resource(
  'Vpc',
  'AWS::EC2::VPC',
  {
    'CidrBlock': options['VpcCidr'],
    "EnableDnsHostnames" : options['DnsHostNames'],
    'Tags':[{'Key':'Name', 'Value':ref('AWS::StackName')}]
  })
)

# Figure out the various subnet CIDRs
# Lets' make the sizes of the subnets a constant for now with:
# PrivateSubnet: 8-bits = 256 IPs
# PrivateSubnet: 7-bits = 128 IPs
# PrivateSubnet: 7-bits = 128 IPs
VpcCidr = options['VpcCidr'].split('/')
VpcIp = ip2int(VpcCidr[0])
VpcSize = 32-int(VpcCidr[1])
assert (VpcIp % (1<<VpcSize)) == 0

PrivateSubnetList = options['PrivateSubnets']
PublicSubnetList = options['PublicSubnets']
SubnetNames = []
PrivateRouteTables = []
PublicRouteTables = []

for pvtsubnet in PrivateSubnetList:
  SubnetNames.append(pvtsubnet)
  PrivateRouteTables.append(pvtsubnet[0]+'RT')
for pubsubnet in PublicSubnetList:
  SubnetNames.append(pubsubnet)
  PublicRouteTables.append(pubsubnet[0]+'RT')

RouteTables = PrivateRouteTables+ PublicRouteTables

CidrSizes={}
for sb in SubnetNames:
  CidrSizes[sb[0]] = options['SubnetSize']

SubnetCidr={}

for subId, subnet in enumerate(SubnetNames):
  for az in [0,1]:
    SubnetCidr[subnet[0]+str(az)] = {}
    ip_offset = (subnet[1] + az) << CidrSizes[subnet[0]]
    SubnetCidr[subnet[0]+str(az)]['ip'] = int2ip(VpcIp + ip_offset)
    SubnetCidr[subnet[0]+str(az)]['size'] = CidrSizes[subnet[0]]

# create the subnets
for az in [0,1]:
  for subname in SubnetNames:
    subnet = subname[0]+str(az)
    cft.resources.add(Resource(
      subnet,
      'AWS::EC2::Subnet',
      {
        'VpcId':ref('Vpc'),
        'CidrBlock': SubnetCidr[subnet]['ip']+'/'+str(32 - SubnetCidr[subnet]['size']),
        'AvailabilityZone': AvailabilityZones[az],
        'Tags':[ 
          {'Key':'Name', 'Value':join('-',ref('AWS::StackName'),subnet)} ]
      })
    )

# Put in the networking 
# Create internet and VPN gateways
cft.resources.add(Resource(
  'InternetGateway',
  'AWS::EC2::InternetGateway',
	{
		'Tags':[{'Key':'Name', 'Value':ref('AWS::StackName')}]
	})
)

# Attach the gateways
cft.resources.add(Resource(
  'AttachIgw',
  'AWS::EC2::VPCGatewayAttachment',
  {
    'VpcId': ref('Vpc'),
    'InternetGatewayId': ref('InternetGateway')
  })
)

# Create the routing tables
for route_table in ['PrivateRT', 'PublicRT']:
  cft.resources.add(Resource(
    route_table,
    'AWS::EC2::RouteTable',
    {
      'VpcId':ref('Vpc'),
      'Tags':[ {'Key':'Name', 'Value':join('-',ref('AWS::StackName'),route_table)} ]
    })
  )

# Add routes to the route tables
# Route to the internet
for route_table in ['PublicRT']:
  cft.resources.add(Resource(
    route_table+'IgwRoute',
    'AWS::EC2::Route',
    {
      'RouteTableId': ref(route_table),
      'DestinationCidrBlock': '0.0.0.0/0',
      'GatewayId': ref( 'InternetGateway' )
    })
  )

#rt_associations = {
#    'ADAssociation0' :{'SubnetId':'ADSubnet0','RouteTableId':'PrivateRT'},
#    'ADAssociation1' :{'SubnetId':'ADSubnet1','RouteTableId':'PrivateRT'},
#    'DeepnetAssociation0' :{'SubnetId':'DeepnetSubnet0','RouteTableId':'PrivateRT'},
#    'DeepnetAssociation1' :{'SubnetId':'DeepnetSubnet1','RouteTableId':'PrivateRT'},
#    'AdminAssociation0':{'SubnetId':'AdminSubnet0','RouteTableId':'PrivateRT'},
#    'AdminAssociation1':{'SubnetId':'AdminSubnet1','RouteTableId':'PrivateRT'},
#    'FilerAssociation0':{'SubnetId':'FilerSubnet0','RouteTableId':'PrivateRT'},
#    'FilerAssociation1':{'SubnetId':'FilerSubnet1','RouteTableId':'PrivateRT'},
#    'NatAssociation0':{'SubnetId':'NatSubnet0','RouteTableId':'PublicRT'},
#    'NatAssociation1':{'SubnetId':'NatSubnet1','RouteTableId':'PublicRT'},
#}
rt_associations = {
  'PrivateAssociation0' :{'SubnetId':'PrivateSubnet0','RouteTableId':'PrivateRT'},
  'PrivateAssociation1' :{'SubnetId':'PrivateSubnet1','RouteTableId':'PrivateRT'},
  'PublicAssociation0':{'SubnetId':'PublicSubnet0','RouteTableId':'PublicRT'},
  'PublicAssociation1':{'SubnetId':'PublicSubnet1','RouteTableId':'PublicRT'},
  'PublicDHCPAssociation0':{'SubnetId':'PublicDHCPSubnet0','RouteTableId':'PublicRT'},
  'PublicDHCPAssociation1':{'SubnetId':'PublicDHCPSubnet1','RouteTableId':'PublicRT'}
}
###

for association in rt_associations.keys():
  cft.resources.add(Resource(
    association,
    'AWS::EC2::SubnetRouteTableAssociation',
    {
      'SubnetId': ref(rt_associations[association]['SubnetId']),
      'RouteTableId': ref(rt_associations[association]['RouteTableId']),
    })
  )
####

SecurityGroupList = options['SecurityGroups']
for sg in SecurityGroupList:
  SgRuleList=[]
  for x in range(2,len(sg)):
    SgRuleDict={}
    SgRuleDict['IpProtocol'] = str(sg[x][0])
    SgRuleDict['FromPort'] = str(sg[x][1])
    SgRuleDict['ToPort'] = str(sg[x][2])
    if re.search(cidrregex,sg[x][3]):
      SgRuleDict['CidrIp'] = str(sg[x][3])
    else:
      SgRuleDict['SourceSecurityGroupId'] = ref(sg[x][3])
    SgRuleList.append(SgRuleDict)
  
  cft.resources.add(Resource(
    sg[0],
    'AWS::EC2::SecurityGroup',
    {
      'VpcId': { 'Ref': 'Vpc' },
      'GroupDescription': sg[1],
      'SecurityGroupIngress': SgRuleList,
      'Tags':[ {'Key':'Name', 'Value':join('-',ref('AWS::StackName'),sg[0])} ]
    })
  )
###

if options['Nat'] == True:
  cft.parameters.add(Parameter(
    "NATInstanceType", 'String',
    {
      "Default": options['NatInstanceType'],
      "Description" : "Size of NAT Instance",
      "Type": "String",
      "ConstraintDescription" : "must be valid instance type."
    })
  )
  cft.parameters.add(Parameter(
    "NATKeyPair", 'String',
    {
      "Default": options['NatKeyPair'],
      "Description" : "NAT instance keypair",
      "Type": "String",
      "ConstraintDescription" : "must be a valid keypair"
    })
  )
  
  cft.resources.add(Resource(
    'NatInstanceRole',
    'AWS::IAM::Role',
    {
      'AssumeRolePolicyDocument':{
        'Statement':[
          {'Effect': 'Allow',
            'Principal': {
              'Service': [ 'ec2.amazonaws.com' ]
            },
            'Action': [ 'sts:AssumeRole' ]}
        ]
      },
      'Path': '/',
      'Policies': [{
        'PolicyName': 'ManageENI',
        'PolicyDocument': {
          'Statement': [{
            'Effect': 'Allow',
            'Resource': '*',
            "Action": [
              "ec2:DescribeAddresses",
              "ec2:AssociateAddress",
              "ec2:AssociateRouteTable",
              "ec2:DeleteRoute",
              "ec2:CreateRoute",
              "ec2:DescribeRouteTables",
              "ec2:ReplaceRoute",
              "ec2:ModifyInstanceAttribute"
            ]
          }]
        }
      }]
    })
  )
   
  cft.resources.add(Resource(
    'NatInstanceProfile',
    'AWS::IAM::InstanceProfile',
    {
      'Path': '/',
      'Roles': [{ 'Ref': 'NatInstanceRole' }]
    })
  )
   
  cft.resources.add(Resource(
    'NatIpAddress',
    'AWS::EC2::EIP',
    {
      'Domain': 'vpc'
    },
    DependsOn('InternetGateway'))
  )

  cft.resources.add(Resource(
    'NatLc',
    'AWS::AutoScaling::LaunchConfiguration',
    {
      'AssociatePublicIpAddress': True,
      'IamInstanceProfile' : ref('NatInstanceProfile'),
      'ImageId' :  { "Fn::FindInMap" : [ "NATAMI", { "Ref" : "AWS::Region" }, "AMI" ]},
      'InstanceType' : ref('NATInstanceType'),
      'KeyName' : ref('NATKeyPair'),
      'SecurityGroups' : [ref('NatSg')],
      'UserData':base64(join('',
        "#!/bin/bash \n",
        "exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1 \n",
        "INS_ID=`curl http://169.254.169.254/latest/meta-data/instance-id`\n",
        "yum update -y \n",
        "REGION=",
        {
          "Ref": "AWS::Region"
        },
        "\n",
        "VPC_ID=",
        {
          "Ref": "Vpc"
        },
        "\n",
        "APPSUBNET_RT=",
        {
          "Ref": "PrivateRT"
        },
        "\n",
        "EIP=",
        {
          "Ref": "NatIpAddress"
        },
        "\n",
        "for RT_ID in $APPSUBNET_RT\n",
        "do\n",
        "aws ec2 delete-route   --destination-cidr-block 0.0.0.0/0 --route-table-id $RT_ID --region $REGION\n",
        "aws ec2 create-route --route-table-id $RT_ID --destination-cidr-block 0.0.0.0/0 --instance-id $INS_ID --region $REGION\n",
        "done\n",
        "EIP_ALLOC=`aws ec2 describe-addresses --public-ips $EIP --region $REGION --output text --query Addresses[*].AllocationId`\n",
        "aws ec2 associate-address --instance-id $INS_ID --allocation-id  $EIP_ALLOC  --region $REGION --allow-reassociation\n",
        "aws ec2 modify-instance-attribute --instance-id $INS_ID --source-dest-check \"{\\\"Value\\\": false}\" --region $REGION\n"
      ))
    })
  )

  cft.resources.add(Resource(
    'NatAsg',
    'AWS::AutoScaling::AutoScalingGroup',
    {
      'AvailabilityZones': [AvailabilityZones[1],AvailabilityZones[0]],
      "HealthCheckType": "EC2",
      "LaunchConfigurationName": ref("NatLc"),
      "MinSize": 1,
      "MaxSize": 1,
      "DesiredCapacity": 1,
      "VPCZoneIdentifier": [ ref("PublicDHCPSubnet1"), ref("PublicDHCPSubnet0")],
      "Tags": [
          { "Key": "Name", "Value": join("-", ref('AWS::StackName'),"nat"), "PropagateAtLaunch": "true" },
      ]
    })
  )
####

if options['AD'] == True:
  cft.parameters.add(Parameter(
    "ADInstanceType", 'String',
    {
      "Default": "t2.medium" if options['ADInstanceType'] == 'NONE' else options['ADInstanceType'],
      "Description" : "Size of the AD Instance",
      "Type": "String",
      "ConstraintDescription" : "must be valid instance type."
    })
  )
  cft.parameters.add(Parameter(
    "ADKeyPair", 'String',
    {
      "Default": options['ADKeyPair'],
      "Description" : "AD instance keypair",
      "Type": "String",
      "ConstraintDescription" : "must be a valid keypair"
    })
  )
  cft.parameters.add(Parameter(
    "ADAMI", 'String',
    {
      "Default": options['ADAMI'],
      "Description" : "AD instance AMI id",
      "Type": "String",
      "ConstraintDescription" : "must be a valid ami"
    })
  )

  cft.resources.add(Resource(
    'ADRole',
    'AWS::IAM::Role',
    {
      'AssumeRolePolicyDocument':{
        'Statement':[
          {'Effect': 'Allow',
            'Principal': {
              'Service': [ 'ec2.amazonaws.com' ]
            },
            'Action': [ 'sts:AssumeRole' ]
          }
        ]
      },
      'Path': '/',
      'Policies': [{
        'PolicyName': 'ADAccess',
        'PolicyDocument': {
          'Statement': [{
            'Effect': 'Allow',
            'Resource': '*',
            'Action': [ 's3:GetBucketLocation', 's3:GetBucketAcl', 's3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions', 's3:PutObject', 's3:PutObjectAcl' ]
          }]
        }
      }]
    })
  )
 
  cft.resources.add(Resource(
    'ADProfile',
    'AWS::IAM::InstanceProfile',
    {
      'Path': '/',
      'Roles': [{ 'Ref': 'ADRole' }]
    })
  )
  
#  cft.resources.add(Resource(
#    'ADEth0',
#    'AWS::EC2::NetworkInterface',
#    {
#      "Description" : join('-',ref('AWS::StackName'), "ADEth0"),
#      "GroupSet" : [ ref(options['ADSecurityGroup'])],
#      "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PrivateSubnet0']['ip']) + 10),
#      "SourceDestCheck" : "False",
#      "SubnetId" : {"Ref" :"PrivateSubnet0"}
#    })
#  )

  cft.resources.add(Resource(
    'ADServer',
    'AWS::EC2::Instance',
    {
      "ImageId" : { "Ref" :"ADAMI"},
      "InstanceType" : {"Ref" :"ADInstanceType"},
      "KeyName" : {"Ref" :"ADKeyPair"}, 
#     "SecurityGroupIds" : [ ref(options['ADSecurityGroup'])],
     "SourceDestCheck" : "False",
      "IamInstanceProfile" : ref('ADProfile'),
#     "SubnetId" : {"Ref" :"PrivateSubnet0"},
      "EbsOptimized" : "false",
      "BlockDeviceMappings" : [{
        "DeviceName" : "/dev/sda1",
        "Ebs" : {"VolumeType" : "gp2", "DeleteOnTermination" : "false", "VolumeSize" : "40"}
      }],
      "NetworkInterfaces" : [{
        "Description" : join('-',ref('AWS::StackName'), "ADEth0"),
        "DeviceIndex" : "0",
        "GroupSet" : [ ref(options['ADSecurityGroup'])],
        "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PrivateSubnet0']['ip']) + 10),
        "SubnetId" : {"Ref" :"PrivateSubnet0"}
      }],
      "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
        {"Key":"Name", "Value": join('-',ref('AWS::StackName'), "ADServer")}],
      "UserData" : {"Fn::Base64" : {"Fn::Join" : ["", [
        "<script>\n",
          "cfn-init.exe -v -s ", {"Ref" : "AWS::StackId"}, " -r ADServer --region ", {"Ref" : "AWS::Region"}, "\n",
        "</script>\n",
        "<powershell>\n",
          "Set-ExecutionPolicy RemoteSigned -Force \n",
          "c:\\temp\\RenameComputer.ps1 DC1 \n",
        "</powershell>\n"
      ]]}}
    },
    [
      Metadata({
        "AWS::CloudFormation::Init" : {
          "config" : {
            "files" : {
              "c:\\temp\\RenameComputer.ps1" : {
                "source" : "https://rw-devops.s3.amazonaws.com/scripts/RenameComputer.ps1",
                "authentication" : "ADS3Creds"
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication" : {
          "ADS3Creds" : {
            "type" : "S3",
            "buckets" : [options['S3Bucket']],
            "roleName" : {"Ref" : "ADRole"}
          }
        }
      })
    ])
  )
####

  cft.resources.add(Resource(
    'AD2Server',
    'AWS::EC2::Instance',
    {
      "ImageId" : { "Ref" :"ADAMI"},
      "InstanceType" : {"Ref" :"ADInstanceType"},
      "KeyName" : {"Ref" :"ADKeyPair"}, 
      "IamInstanceProfile" : ref('ADProfile'),
      "EbsOptimized" : "false",
      "SourceDestCheck" : "false",
      "BlockDeviceMappings" : [{
        "DeviceName" : "/dev/sda1",
        "Ebs" : {"VolumeType" : "gp2", "DeleteOnTermination" : "false", "VolumeSize" : "40"}
      }],
      "NetworkInterfaces" : [{
        "Description" : join('-',ref('AWS::StackName'), "AD2Eth0"),
        "DeviceIndex" : "0",
        "GroupSet" : [ ref(options['ADSecurityGroup'])],
        "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PrivateSubnet1']['ip']) + 10),
        "SubnetId" : {"Ref" :"PrivateSubnet1"}
      }],
      "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
        {"Key":"Name", "Value": join('-',ref('AWS::StackName'), "AD2Server")}
      ],
      "UserData" : {"Fn::Base64" : {"Fn::Join" : ["", [
        "<script>\n",
          "cfn-init.exe -v -s ", {"Ref" : "AWS::StackId"}, " -r AD2Server --region ", {"Ref" : "AWS::Region"}, "\n",
        "</script>\n",
        "<powershell>\n",
          "Set-ExecutionPolicy RemoteSigned -Force \n",
          "c:\\temp\\RenameComputer.ps1 DC2 \n",
        "</powershell>\n"
      ]]}}
    },
    [
      Metadata({
        "AWS::CloudFormation::Init" : {
          "config" : {
            "files" : {
              "c:\\temp\\RenameComputer.ps1" : {
                "source" : "https://rw-devops.s3.amazonaws.com/scripts/RenameComputer.ps1",
                "authentication" : "AD2S3Creds"
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication" : {
          "AD2S3Creds" : {
            "type" : "S3",
            "buckets" : [options['S3Bucket']],
            "roleName" : {"Ref" : "ADRole"}
          }
        }
      })
    ])
  )
####

if options['Admin'] == True:
  cft.parameters.add(Parameter(
    "AdminInstanceType", 'String',
    {
      "Default": "t2.medium" if options['AdminInstanceType'] == 'NONE' else options['AdminInstanceType'],
      "Description" : "Size of the Admin Instance",
      "Type": "String",
      "ConstraintDescription" : "must be valid instance type."
    })
  )
  cft.parameters.add(Parameter(
    "AdminKeyPair", 'String',
    {
      "Default": options['AdminKeyPair'],
      "Description" : "Admin instance keypair",
      "Type": "String",
      "ConstraintDescription" : "must be a valid keypair"
    })
  )
  cft.parameters.add(Parameter(
    "AdminAMI", 'String',
    {
      "Default": options['AdminAMI'],
      "Description" : "Admin instance AMI id",
      "Type": "String",
      "ConstraintDescription" : "must be a valid ami"
    })
  )

  cft.resources.add(Resource(
    'AdminRole',
    'AWS::IAM::Role',
    {
      'AssumeRolePolicyDocument':{
        'Statement':[
          {'Effect': 'Allow',
            'Principal': {
            'Service': [ 'ec2.amazonaws.com' ]
          },
          'Action': [ 'sts:AssumeRole' ]}
        ]
      },
      'Path': '/',
      'Policies': [{
        'PolicyName': 'AdminAccess',
        'PolicyDocument': {
          'Statement': [{
            'Effect': 'Allow',
            'Resource': '*',
            'Action': [ 's3:GetBucketLocation', 's3:GetBucketAcl', 's3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions', 's3:PutObject', 's3:PutObjectAcl' ]
          }]
        }
      }]
    })
  )

  cft.resources.add(Resource(
    'AdminProfile',
    'AWS::IAM::InstanceProfile',
    {
        'Path': '/',
        'Roles': [{ 'Ref': 'AdminRole' }]
    })
  )
  
  cft.resources.add(Resource(
    'AdminServer',
    'AWS::EC2::Instance',
    {
      "ImageId" : { "Ref" :"AdminAMI"},
      "InstanceType" : {"Ref" :"AdminInstanceType"},
      "KeyName" : {"Ref" :"AdminKeyPair"},
      "IamInstanceProfile" : ref('AdminProfile'),
      "EbsOptimized" : "false",
      "SourceDestCheck" : "False",
      "BlockDeviceMappings" : [{
        "DeviceName" : "/dev/sda1",
        "Ebs" : {"VolumeType" : "gp2", "DeleteOnTermination" : "false", "VolumeSize" : "40"}
      }],
      "NetworkInterfaces" : [{
        "AssociatePublicIpAddress" : "true",
        "Description" : join('-',ref('AWS::StackName'), "AdminEth0"),
        "DeviceIndex" : "0",
        "GroupSet" : [ ref(options['AdminSecurityGroup'])],
        "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PublicSubnet0']['ip']) + 20),
        "SubnetId" : {"Ref" :"PublicSubnet0"}
      }],
      "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
        {"Key":"Name", "Value": join('-',ref('AWS::StackName'), "AdminServer")}],
      "UserData" : {"Fn::Base64" : {"Fn::Join" : ["", [
        "<script>\n",
          "cfn-init.exe -v -s ", {"Ref" : "AWS::StackId"}, " -r AdminServer --region ", {"Ref" : "AWS::Region"}, "\n",
        "</script>\n",
        "<powershell>\n",
          "Set-ExecutionPolicy RemoteSigned -Force \n",
          "c:\\temp\\RenameComputer.ps1 ADMIN1 \n",
        "</powershell>\n"
      ]]}}
    },
    [
      Metadata({
        "AWS::CloudFormation::Init" : {
          "config" : {
            "files" : {
              "c:\\temp\\RenameComputer.ps1" : {
                "source" : "https://rw-devops.s3.amazonaws.com/scripts/RenameComputer.ps1",
                "authentication" : "AdminS3Creds"
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication" : {
          "AdminS3Creds" : {
            "type" : "S3",
            "buckets" : [options['S3Bucket']],
            "roleName" : {"Ref" : "AdminRole"}
          }
        }
      }),
      DependsOn('AttachIgw')
    ])
  )
####

if options['Filer'] == True:
  cft.parameters.add(Parameter(
    "FilerInstanceType", 'String',
    {
      "Default": "t2.medium" if options['FilerInstanceType'] == 'NONE' else options['FilerInstanceType'],
      "Description" : "Size of the Filer Instance",
      "Type": "String",
      "ConstraintDescription" : "must be valid instance type."
    })
  )
  cft.parameters.add(Parameter(
    "FilerKeyPair", 'String',
    {
      "Default": options['FilerKeyPair'],
      "Description" : "Filer instance keypair",
      "Type": "String",
      "ConstraintDescription" : "must be a valid keypair"
    })
  )
  cft.parameters.add(Parameter(
    "FilerAMI", 'String',
    {
      "Default": options['FilerAMI'],
      "Description" : "Filer instance AMI id",
      "Type": "String",
      "ConstraintDescription" : "must be a valid ami"
    })
  )

  cft.resources.add(Resource(
    'FilerRole',
    'AWS::IAM::Role',
    {
      'AssumeRolePolicyDocument':{
        'Statement':[
          {'Effect': 'Allow',
            'Principal': {
               'Service': [ 'ec2.amazonaws.com' ]
            },
            'Action': [ 'sts:AssumeRole' ]}
        ]
      },
      'Path': '/',
      'Policies': [{
        'PolicyName': 'FilerAccess',
        'PolicyDocument': {
          'Statement': [{
            'Effect': 'Allow',
            'Resource': '*',
            'Action': [ 's3:GetBucketLocation', 's3:GetBucketAcl', 's3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions', 's3:PutObject', 's3:PutObjectAcl' ]
          }]
        }
      }]
    })
  )

  cft.resources.add(Resource(
    'FilerProfile',
    'AWS::IAM::InstanceProfile',
    {
      'Path': '/',
      'Roles': [{ 'Ref': 'FilerRole' }]
    })
  )

  cft.resources.add(Resource(
    'FilerServer',
    'AWS::EC2::Instance',
    {
      "ImageId" : { "Ref" :"FilerAMI"},
      "InstanceType" : {"Ref" :"FilerInstanceType"},
      "KeyName" : {"Ref" :"FilerKeyPair"},
      "IamInstanceProfile" : ref('FilerProfile'),
      "EbsOptimized" : "false",
      "SourceDestCheck" : "False",
      "BlockDeviceMappings" : [{
        "DeviceName" : "/dev/sda1",
        "Ebs" : {"VolumeType" : "gp2", "DeleteOnTermination" : "false", "VolumeSize" : "40"}
      }],
      "NetworkInterfaces" : [{
        "Description" : join('-',ref('AWS::StackName'), "FilerEth0"),
        "DeviceIndex" : "0",
        "GroupSet" : [ ref(options['FilerSecurityGroup'])],
        "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PrivateSubnet0']['ip']) + 40),
        "SubnetId" : {"Ref" :"PrivateSubnet0"}
      }],
      "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
        {"Key":"Name", "Value": join('-',ref('AWS::StackName'), "FilerServer")}],
      "UserData" : {"Fn::Base64" : {"Fn::Join" : ["", [
        "<script>\n",
          "cfn-init.exe -v -s ", {"Ref" : "AWS::StackId"}, " -r FilerServer --region ", {"Ref" : "AWS::Region"}, "\n",
        "</script>\n",
        "<powershell>\n",
          "Set-ExecutionPolicy RemoteSigned -Force \n",
          "c:\\temp\\RenameComputer.ps1 FILER1 \n",
        "</powershell>\n"
      ]]}}
    },
    [
      Metadata({
        "AWS::CloudFormation::Init" : {
          "config" : {
            "files" : {
              "c:\\temp\\RenameComputer.ps1" : {
                "source" : "https://rw-devops.s3.amazonaws.com/scripts/RenameComputer.ps1",
                "authentication" : "FilerS3Creds"
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication" : {
          "FilerS3Creds" : {
            "type" : "S3",
            "buckets" : [options['S3Bucket']],
            "roleName" : {"Ref" : "FilerRole"}
          }
        }
      })
    ])
 )
####

if options['Deepnet'] == True:
  cft.parameters.add(Parameter(
    "DeepnetInstanceType", 'String',
    {
      "Default": "t2.medium" if options['DeepnetInstanceType'] == 'NONE' else options['DeepnetInstanceType'],
      "Description" : "Size of the Deepnet Instance",
      "Type": "String",
      "ConstraintDescription" : "must be valid instance type."
    })
  )
  cft.parameters.add(Parameter(
    "DeepnetKeyPair", 'String',
    {
      "Default": options['DeepnetKeyPair'],
      "Description" : "Deepnet instance keypair",
      "Type": "String",
      "ConstraintDescription" : "must be a valid keypair"
    })
  )
  cft.parameters.add(Parameter(
    "DeepnetAMI", 'String',
    {
      "Default": options['DeepnetAMI'],
      "Description" : "Deepnet instance AMI id",
      "Type": "String",
      "ConstraintDescription" : "must be a valid ami"
    })
  )

  cft.resources.add(Resource(
    'DeepnetRole',
    'AWS::IAM::Role',
    {
      'AssumeRolePolicyDocument':{
        'Statement':[
          {'Effect': 'Allow',
            'Principal': {
              'Service': [ 'ec2.amazonaws.com' ]
            },
            'Action': [ 'sts:AssumeRole' ]}
        ]
      },
      'Path': '/',
      'Policies': [{
        'PolicyName': 'DeepnetAccess',
        'PolicyDocument': {
          'Statement': [{
            'Effect': 'Allow',
            'Resource': '*',
            'Action': [ 's3:GetBucketLocation', 's3:GetBucketAcl', 's3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions', 's3:PutObject', 's3:PutObjectAcl' ]
          }]
        }
      }]
    })
  )

  cft.resources.add(Resource(
    'DeepnetProfile',
    'AWS::IAM::InstanceProfile',
    {
      'Path': '/',
      'Roles': [{ 'Ref': 'DeepnetRole' }]
    })
  )

  cft.resources.add(Resource(
    'DeepnetServer',
    'AWS::EC2::Instance',
    {
      "ImageId" : { "Ref" :"DeepnetAMI"},
      "InstanceType" : {"Ref" :"DeepnetInstanceType"},
      "KeyName" : {"Ref" :"DeepnetKeyPair"},
      "IamInstanceProfile" : ref('DeepnetProfile'),
      "EbsOptimized" : "false",
      "SourceDestCheck" : "False",
      "BlockDeviceMappings" : [{
        "DeviceName" : "/dev/sda1",
        "Ebs" : {"VolumeType" : "gp2", "DeleteOnTermination" : "false", "VolumeSize" : "40"}
      }],
      "NetworkInterfaces" : [{
        "Description" : join('-',ref('AWS::StackName'), "DeepnetEth0"),
        "DeviceIndex" : "0",
        "GroupSet" : [ ref(options['DeepnetSecurityGroup'])],
        "PrivateIpAddress" : int2ip(ip2int(SubnetCidr['PrivateSubnet0']['ip']) + 30),
        "SubnetId" : {"Ref" :"PrivateSubnet0"}
      }],
      "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
        {"Key":"Name", "Value": join('-',ref('AWS::StackName'), "DeepnetServer")}],
      "UserData" : {"Fn::Base64" : {"Fn::Join" : ["", [
        "<script>\n",
          "cfn-init.exe -v -s ", {"Ref" : "AWS::StackId"}, " -r DeepnetServer --region ", {"Ref" : "AWS::Region"}, "\n",
        "</script>\n",
        "<powershell>\n",
          "Set-ExecutionPolicy RemoteSigned -Force \n",
          "c:\\temp\\RenameComputer.ps1 DEEPNET1 \n",
        "</powershell>\n"
      ]]}}
    },
    [
      Metadata({
        "AWS::CloudFormation::Init" : {
          "config" : {
            "files" : {
              "c:\\temp\\RenameComputer.ps1" : {
                "source" : "https://rw-devops.s3.amazonaws.com/scripts/RenameComputer.ps1",
                "authentication" : "DeepnetS3Creds"
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication" : {
          "DeepnetS3Creds" : {
            "type" : "S3",
            "buckets" : [options['S3Bucket']],
            "roleName" : {"Ref" : "DeepnetRole"}
          }
        }
      })
    ])
  )
####
#############################Create VPC Peering #####################################################
cft.parameters.add(Parameter(
  "SvcVPCId", 'String',
  {
    "Default": "vpc-xxxxxxxx",
    "Description" : "VPC Id of the network which has services like jenkins and VPN",
    "Type": "String",
    "ConstraintDescription" : "Valid VPC Id"
  })
)
cft.parameters.add(Parameter(
  "SvcRT", 'String',
  {
    "Default": "rtb-xxxxxxxx",
    "Description" : "Route Table ID of the network which has services like jenkins and VPN",
    "Type": "String",
    "ConstraintDescription" : "Valid Route Table ID"
  })
)

cft.resources.add(Resource(
  'VPNVPCPeering',
  "AWS::EC2::VPCPeeringConnection",
  {
    "VpcId": ref('Vpc'),
    "PeerVpcId": ref('SvcVPCId'),
    "Tags": [
      {
        "Key" : "Name",
        "Value" : join('-',ref("AWS::StackName"),"svc")
      }
    ]   
  }
))

##modify the routes to connect to the peering VPC
for route_table in ['PublicRT','PrivateRT']:
  cft.resources.add(Resource(
    route_table + 'VPCPeerRoute',
    'AWS::EC2::Route',
    {
      'RouteTableId': ref(route_table),
      'DestinationCidrBlock': options['PeeringCidr'],
      'VpcPeeringConnectionId': ref('VPNVPCPeering'),
    })
  )

cft.resources.add(Resource(
  'VPNVPCPeerRoute',
  'AWS::EC2::Route',
  {
    'RouteTableId':ref('SvcRT'),
    'DestinationCidrBlock': options['VpcCidr'],
    'VpcPeeringConnectionId': ref('VPNVPCPeering'),
  })
)

##outputs##
cft.outputs.add(
  Output('Cell0VPCId',
    ref('Vpc')
  )
)

cft.outputs.add(
  Output('Cell0PrivateRT',
    ref('PrivateRT')
  )
)

cft.outputs.add(
  Output('Cell0PublicRT',
    ref('PublicRT')
  )
)
