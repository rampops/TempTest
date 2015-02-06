# Constant definition
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


VPC_CIDR = '10.60.0.0/16'

# Start of the CloudFormation template
description = 'CloudFormation template for creating the VPC - Services'
cft = CloudFormationTemplate(description=description)

cft.parameters.add(Parameter(
    "OpenVpnKeyName", 'String',
    {
      "Description" : "Name of an existing EC2 KeyPair to enable SSH access to OpenVpn Server",
      "Default": options['KeyPair'],
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "255",
      "AllowedPattern" : "[\\x20-\\x7E]*",
      "ConstraintDescription" : "can contain only ASCII characters."
    })
)

cft.parameters.add(Parameter(
    "OpenVpnInstanceType", 'String',
    {
      "Default": options['OpenVpnInstanceType'],
      "Description" : "Instance type of OpenVPN",
      "Type": "String",
      "ConstraintDescription" : "Valid instance type."
    })
)

cft.parameters.add(Parameter(
    "JenkinsKeyName", 'String',
    {
      "Description" : "Name of an existing EC2 KeyPair to enable SSH access to Jenkins Server",
      "Default": options['KeyPair'],
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "255",
      "AllowedPattern" : "[\\x20-\\x7E]*",
      "ConstraintDescription" : "can contain only ASCII characters."
    })
)

cft.parameters.add(Parameter(
    "JenkinsInstanceType", 'String',
    {
      "Default": options['JenkinsInstanceType'],
      "Description" : "Instance type of Jenkins",
      "Type": "String",
      "ConstraintDescription" : "Valid instance type."
    })
)

cft.parameters.add(Parameter(
    "JenkinsAMI", 'String',
    {
      "Description" : "AMI to be used for Jenkins",
      "Default": options['JenkinsAmi'],
      "Type": "String",
      "ConstraintDescription" : "Valid AMI ID",
      "AllowedPattern": "ami-[a-z0-9]+"
    })
)

cft.parameters.add(Parameter(
    "OpenvpnServerAMI", 'String',
    {
      "Description" : "AMI to be used for Open VPN Server",
      "Default" : options['OpenVpnAmi'],
      "Type": "String",
      "ConstraintDescription" : "Valid AMI ID",
      "AllowedPattern": "ami-[a-z0-9]+"
    })
)




# ###########################
# ## The Resources Section ##
# ###########################
# Create VPC
cft.resources.add(Resource(
    'Vpc',
    'AWS::EC2::VPC',
    {
        'CidrBlock': VPC_CIDR,
        'Tags':[{'Key':'Name', 'Value':ref('AWS::StackName')}]
    })
)
#VpcCidr = '10.60.0.0/16'.split('/')
VpcCidr = VPC_CIDR.split('/')
VpcIp = ip2int(VpcCidr[0])
VpcSize = 32-int(VpcCidr[1])
assert (VpcIp % (1<<VpcSize)) == 0
SubnetNames=['SvcSubnet']
CidrSizes={
	'SvcSubnet':8
}
SubnetCidr={}
ip_offset = 2560

for az in [0,1]:    
    for subnet in SubnetNames:
        SubnetCidr[subnet+str(az)] = {}
        SubnetCidr[subnet+str(az)]['ip'] = int2ip(VpcIp + ip_offset)
        SubnetCidr[subnet+str(az)]['size'] = CidrSizes[subnet]
        ip_offset = ip_offset + (1<<CidrSizes[subnet])

for az in [0,1]:    
    for subname in SubnetNames:
        subnet = subname+str(az)
        cft.resources.add(Resource(
            subnet,
            'AWS::EC2::Subnet',
            {
                'VpcId':ref('Vpc'),
                'CidrBlock': SubnetCidr[subnet]['ip']+'/'+str(32 - SubnetCidr[subnet]['size']),
                'AvailabilityZone': AvailabilityZones[az],
                'Tags':[ {'Key':'Name', 'Value':join('-',ref('AWS::StackName'),subnet)} ]
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
cft.resources.add(Resource(
	'SvcRT',
	'AWS::EC2::RouteTable',
	{
		'VpcId':ref('Vpc'),
		'Tags':[ {'Key':'Name', 'Value':join('-',ref('AWS::StackName'),'SvcRT')} ]
	})
)

# Add routes to the route tables
# Route to the internet
for route_table in ['SvcRT']:
    cft.resources.add(Resource(
        route_table+'IgwRoute',
        'AWS::EC2::Route',
        {
            'RouteTableId': ref(route_table),
            'DestinationCidrBlock': '0.0.0.0/0',
            'GatewayId': ref( 'InternetGateway' )
		})
	)
# Attach the route tables
rt_associations = {
	'SvcAssociation0' :{'SubnetId':'SvcSubnet0','RouteTableId':'SvcRT'},
    'SvcAssociation1' :{'SubnetId':'SvcSubnet1','RouteTableId':'SvcRT'}
}
for association in rt_associations.keys():
    cft.resources.add(Resource(
        association,
        'AWS::EC2::SubnetRouteTableAssociation',
        {
            'SubnetId': ref(rt_associations[association]['SubnetId']),
            'RouteTableId': ref(rt_associations[association]['RouteTableId']),
        })
    )
# OpenVpn
cft.resources.add(Resource(
    'openpvpnsg',
    'AWS::EC2::SecurityGroup',
    {
        'VpcId': { 'Ref': 'Vpc' },
        'GroupDescription': 'OpenVPN SG',
        'SecurityGroupIngress': [
            { 'IpProtocol' : 'tcp', 'FromPort' : '943',   'ToPort' : '943',    "CidrIp" : '0.0.0.0/0'  },
            { 'IpProtocol' : 'tcp', 'FromPort' : '443',   'ToPort' : '443',    "CidrIp" : '0.0.0.0/0'  },
            { 'IpProtocol' : 'tcp',  'FromPort' : '22',   'ToPort' : '22',   'CidrIp' : VPC_CIDR },
            { 'IpProtocol' : 'udp',  'FromPort' : '1194',  'ToPort' : '1194',  'CidrIp' : '0.0.0.0/0' }
        ]
    })
)

#Jenkins-SG
cft.resources.add(Resource(
	'jenkinssg',
	'AWS::EC2::SecurityGroup',
    {
        'VpcId': { 'Ref': 'Vpc' },
        'GroupDescription': 'Jenkins SG',
        'SecurityGroupIngress': [
        { 'IpProtocol' : 'tcp', 'FromPort' : '80',   'ToPort' : '80',    "CidrIp" : '10.0.0.0/8'  },
            { 'IpProtocol' : 'tcp', 'FromPort' : '443',   'ToPort' : '443',  'CidrIp' : '10.0.0.0/8' },
            { 'IpProtocol' : 'tcp',  'FromPort' : '22',   'ToPort' : '22',   "SourceSecurityGroupId" : {"Ref" : "openpvpnsg"} },
            { 'IpProtocol' : 'tcp',  'FromPort' : '22',  'ToPort' : '22', "CidrIp" : '10.0.0.0/8' }
        ]
    })
)
# EIP for OpenVPN
cft.resources.add(Resource(
 'EIPOpenvpn',
 'AWS::EC2::EIP',
  {
     "Domain" : "vpc",
     "InstanceId": { "Ref": "OpenVpnServer" }
  })
)

# EIP for OpenVPN
cft.resources.add(Resource(
 'EIPJenkins',
 'AWS::EC2::EIP',
  {
     "Domain" : "vpc",
     "InstanceId": { "Ref": "JenkinsServer" }
  })
)

##### IAM ROles #########################
#create IAM Roles for Jenkins INstance
cft.resources.add(Resource(
	'JenkinsRole',
	'AWS::IAM::Role',
    {
    	 'AssumeRolePolicyDocument':{
    	 	'Statement':[
				{
					'Effect': 'Allow',
					'Principal': {
						'Service': [ 'ec2.amazonaws.com' ]
					},
					'Action': [ 'sts:AssumeRole' ]
				}
			]
		},
		'Path': '/',
		'Policies': [{
			'PolicyName': 'copy',
			'PolicyDocument': {
				"Statement": [
   				{"Resource":"*","Action":"ec2:*","Effect":"Allow"},
   				{"Resource":"*","Action":"s3:*","Effect":"Allow"},
   				{"Resource":"*","Action":"autoscaling:*","Effect":"Allow"},
   				{"Resource":"*","Action":"iam:*","Effect":"Allow"},
   				{"Resource":"*","Action":"elasticloadbalancing:*","Effect":"Allow"},
   				{"Resource":"*","Action":"rds:*","Effect":"Allow"},
   				{"Resource":"*","Action":"cloudformation:*","Effect":"Allow"},
   				{"Resource":"*","Action":"sns:*","Effect":"Allow"},
   				{"Resource":"*","Action":"cloudwatch:*","Effect":"Allow"},
   				{"Resource":"*","Action":"route53:*","Effect":"Allow"},
   				
  		]
		}}]
	})
)

cft.resources.add(Resource(
	'JenkinsProfile',
	'AWS::IAM::InstanceProfile',
	{
		'Path': '/',
		'Roles': [{ 'Ref': 'JenkinsRole' }]
	})
)


##define openvpn Server Role
cft.resources.add(Resource(
	'OpenVPNRole',
	'AWS::IAM::Role',
    {
    	 'AssumeRolePolicyDocument':{
    	 	'Statement':[
				{
					'Effect': 'Allow',
					'Principal': {
						'Service': [ 'ec2.amazonaws.com' ]
					},
					'Action': [ 'sts:AssumeRole' ]
				}
			]
		},
		'Path': '/',
		'Policies': [{
			'PolicyName': 'copy',
			'PolicyDocument': {
				"Statement": [
   				{"Resource":"*","Action":"s3:*","Effect":"Allow"},
  		]
		}}]
	})
)

cft.resources.add(Resource(
	'OpenVPNProfile',
	'AWS::IAM::InstanceProfile',
	{
		'Path': '/',
		'Roles': [{ 'Ref': 'OpenVPNRole' }]
	})
)
		
# Create OpenVpn Server
cft.resources.add(Resource(
  'OpenVpnServer',
  'AWS::EC2::Instance',
  {
    "ImageId" : ref('OpenvpnServerAMI'),
    "InstanceType" :  {"Ref" :"OpenVpnInstanceType"},
    "IamInstanceProfile" : { "Ref" : "OpenVPNProfile" },
    "KeyName" : {"Ref" :"OpenVpnKeyName"},
    "SecurityGroupIds" : [ {"Ref" : "openpvpnsg"}],
    "SourceDestCheck" : "False",
    "SubnetId" : {"Ref" :"SvcSubnet0"},
    "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
	{"Key":"Name","Value": join("-", ref('AWS::StackName'),"openvpn-server")}],
    "UserData"       : { "Fn::Base64" : { "Fn::Join" : ["", [
    	"#!/bin/bash -vx\n",#This is sample user data. Update it as required
    	"exec > >(tee /var/log/userdata.log)\n",
      "exec 2>&1\n",
      "AWS_DEFAULT_REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document|grep region|awk -F\\\" '{print $4}')\n",
      "if [ \"$AWS_DEFAULT_REGION\" == ",options['PrimaryRegion']," ];then\n",
      "DEVOPS_BUCKET=",options['DevOpsPrimaryBucket'],"\n",
      "BACKUP_BUCKET=",options['DevOpsDRBucket'],"\n",
      "BACKUP_REGION=",options['DRRegion'],"\n",
      "IS_PRIMARY_REGION=True\n",
      "elif [ \"$AWS_DEFAULT_REGION\" == ",options['DRRegion']," ];then\n",
      "DEVOPS_BUCKET=",options['DevOpsDRBucket'],"\n",
      "BACKUP_BUCKET=",options['DevOpsPrimaryBucket'],"\n",
      "BACKUP_REGION=",options['PrimaryRegion'],"\n",
      "IS_PRIMARY_REGION=False\n","fi\n",
      "tee /etc/profile.d/devops.sh << EOF\n",
      "#!/bin/bash\n",
      "export AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION\n",
      "export DEVOPS_BUCKET=$DEVOPS_BUCKET\n",
      "export BACKUP_BUCKET=$BACKUP_BUCKET\n",
      "export IS_PRIMARY_REGION=$IS_PRIMARY_REGION\n",
      "export BACKUP_REGION=$BACKUP_REGION\n",
      "EOF\n",
      "apt-get update\n",
      "apt-get install -y python-pip\n",
      "pip install awscli --upgrade\n",
      "service openvpnas stop\n",
      "aws --region $AWS_DEFAULT_REGION s3 sync --recursive s3://$DEVOPS_BUCKET/openvpn-config/etc/ /usr/local/openvpn_as/etc/\n",
      "service openvpnas start\n",
      "PUBLIC_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)\n",
      "/usr/local/openvpn_as/scripts/confdba -m --prof Default -k \"host.name\" -v $PUBLIC_IP\n"
     ]]
    }} 
  })
)

# Create Jenkins Server
	
cft.resources.add(Resource(
	'JenkinsServer',
	'AWS::EC2::Instance',
	{
    "ImageId" : ref('JenkinsAMI'),
    "InstanceType" :  {"Ref" :"JenkinsInstanceType"},
    "IamInstanceProfile" : { "Ref" : "JenkinsProfile" },
    "KeyName" : {"Ref" :"JenkinsKeyName"},
    "SecurityGroupIds" : [ {"Ref" : "jenkinssg"}],
    "SourceDestCheck" : "False",
    "SubnetId" : {"Ref" :"SvcSubnet0"},
    "Tags": [
        {"Key":"EnableBackup", "Value":"True"},
	{"Key":"Name", "Value": join("-", ref('AWS::StackName'),"jenkins-server")}],
    "UserData"       : { "Fn::Base64" : { "Fn::Join" : ["", [
      "#!/bin/bash -vx\n",#This is sample user data. Update it as required
      "exec > >(tee /var/log/userdata.log)\n",
      "exec 2>&1\n",
      "AWS_DEFAULT_REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document|grep region|awk -F\\\" '{print $4}')\n",
      "if [ \"$AWS_DEFAULT_REGION\" == ",options['PrimaryRegion']," ];then\n",
      "DEVOPS_BUCKET=",options['DevOpsPrimaryBucket'],"\n",
      "BACKUP_BUCKET=",options['DevOpsDRBucket'],"\n",
      "BACKUP_REGION=",options['DRRegion'],"\n",
      "IS_PRIMARY_REGION=True\n",
      "elif [ \"$AWS_DEFAULT_REGION\" == ",options['DRRegion']," ];then\n",
      "DEVOPS_BUCKET=",options['DevOpsDRBucket'],"\n",
      "BACKUP_BUCKET=",options['DevOpsPrimaryBucket'],"\n",
      "BACKUP_REGION=",options['PrimaryRegion'],"\n",
      "IS_PRIMARY_REGION=False\n","fi\n",
      "apt-get update\n",
      "apt-get install -y python-pip\n",
      "pip install awscli --upgrade\n",
      "tee /etc/profile.d/devops.sh << EOF\n",
      "#!/bin/bash\n",
      "export AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION\n",
      "export DEVOPS_BUCKET=$DEVOPS_BUCKET\n",
      "export BACKUP_BUCKET=$BACKUP_BUCKET\n",
      "export IS_PRIMARY_REGION=$IS_PRIMARY_REGION\n",
      "export BACKUP_REGION=$BACKUP_REGION\n",
      "EOF\n",
      "service jenkins stop\n",
      "aws --region $AWS_DEFAULT_REGION s3 sync --recursive s3://$DEVOPS_BUCKET/fluxboard-config/ /var/lib/jenkins/\n",
      "service jenkins start\n"
      
     ]]
    }}      
  })
)

##outputs##
cft.outputs.add(
    Output('VPC',
        ref('Vpc')
    )
)

cft.outputs.add(
    Output('SvcRt',
        ref('SvcRT')
    )
)

cft.outputs.add(
      Output( 'OpenVPNAddress',ref('EIPOpenvpn' ))
)
cft.outputs.add(
      Output( 'JenkinsAddress',get_att('JenkinsServer','PrivateIp'))
)

